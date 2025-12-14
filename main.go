package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"math/big"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite" // CGO不要のドライバをインポート
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- 構造体の定義 ---

// クライアントに返すポケモンの情報
type Pokemon struct {
	ID          int          `json:"id"`
	Name        string       `json:"name"` // 日本語名
	EnglishName string       `json:"englishName"`
	Category    string       `json:"-"` // "kanto", "mega", "gmax" など (JSONには含めない)
	Stats       PokemonStats `json:"stats"`
	ImageURL    string       `json:"imageUrl"`
	Height      float32      `json:"height"` // m単位
	Weight      float32      `json:"weight"` // kg単位
	Types       []string     `json:"types"`  // 日本語のタイプ名
}

// ポケモンの種族値
type PokemonStats struct {
	HP        int `json:"hp"`
	Attack    int `json:"attack"`
	Defense   int `json:"defense"`
	SpAttack  int `json:"sp_attack"`
	SpDefense int `json:"sp_defense"`
	Speed     int `json:"speed"`
}

// --- PokeAPIからのレスポンスをパースするための構造体 ---

// /pokemon/{id} のレスポンス
type pokeAPIPokemonResponse struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Stats []struct {
		BaseStat int `json:"base_stat"`
		Stat     struct {
			Name string `json:"name"`
		} `json:"stat"`
	} `json:"stats"`
	Sprites struct {
		Other struct {
			OfficialArtwork struct {
				FrontDefault string `json:"front_default"`
			} `json:"official-artwork"`
		} `json:"other"`
	} `json:"sprites"`
	Species struct {
		URL string `json:"url"`
	} `json:"species"`
	Height float32 `json:"height"`
	Weight float32 `json:"weight"`
	Types  []struct {
		Type struct {
			Name string `json:"name"`
		} `json:"type"`
	} `json:"types"`
}

// /pokemon-species/{id} のレスポンス
type pokeAPISpeciesResponse struct {
	Names []struct {
		Language struct {
			Name string `json:"name"`
		} `json:"language"`
		Name string `json:"name"`
	} `json:"names"`
	Varieties []struct {
		IsDefault bool `json:"is_default"`
		Pokemon   struct {
			Name string `json:"name"`
		} `json:"pokemon"`
	} `json:"varieties"`
}

// /type/{id} のレスポンス
type pokeAPITypeResponse struct {
	Names []struct {
		Language struct {
			Name string `json:"name"`
		} `json:"language"`
		Name string `json:"name"`
	} `json:"names"`
}

// /generation/{id} のレスポンス
type pokeAPIGenerationResponse struct {
	PokemonSpecies []struct {
		Name string `json:"name"`
		// species.URLからIDを抽出するためにURLフィールドを追加
		URL string `json:"url"`
	} `json:"pokemon_species"`
}

// --- データベースモデル ---

type User struct {
	gorm.Model
	Username     string `gorm:"unique;not null"`
	PasswordHash string `gorm:"not null"`
}

type UserStat struct {
	gorm.Model
	UserID         uint   `gorm:"unique;not null"`
	TotalQuestions int    `gorm:"default:0"`
	TotalCorrect   int    `gorm:"default:0"`
	WrongAnswers   string `gorm:"type:text"` // 間違えたポケモンIDをJSON配列の文字列として保存
}

// --- グローバル変数と定数 ---

var db *gorm.DB
var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY")) // 環境変数からJWTキーを読み込む

const TOKEN_DURATION = time.Hour * 24 // トークンの有効期限

// --- グローバル変数 ---

// 地方ごとのポケモンデータを保持する
var pokemonListByRegion = make(map[string][]Pokemon)
var pokemonMapByID = make(map[int]Pokemon) // 全てのポケモンをIDで引けるように保持

// タイプの英語名と日本語名の対応表
var typeNameMap = make(map[string]string)

// 地方名とPokeAPIの世代IDの対応表
var regionGenerationMap = map[string]int{
	"kanto":    1,
	"johto":    2,
	"hoenn":    3,
	"sinnoh":   4,
	"unova":    5,
	"kalos":    6,
	"alola":    7,
	"galar":    8,
	"paldea":   9,
	"mega":     -1, // 特殊カテゴリ
	"gmax":     -2, // 特殊カテゴリ
	"regional": -3, // 特殊カテゴリ
}

const pokemonDataFile = "pokemon.json"

func main() {
	// .envファイルから環境変数を読み込む（ファイルが存在しなくてもエラーにはならない）
	err := godotenv.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("Error loading .env file: %v", err)
	}

	jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(jwtKey) == 0 {
		log.Fatal("FATAL: JWT_SECRET_KEY environment variable is not set.")
	}

	// データベースの初期化
	// Render.comなどのPaaSに対応するため、DATABASE_URL環境変数を使用
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// ローカル開発用にSQLiteにフォールバック
		log.Println("DATABASE_URL is not set. Falling back to SQLite.")
		dsn = "pokemon_quiz.db"
		db, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	} else {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db.AutoMigrate(&User{}, &UserStat{}) // テーブルを自動生成

	// ポケモンデータをファイルから読み込むか、APIから取得する
	if err := loadOrFetchPokemonData(); err != nil {
		log.Fatalf("Failed to initialize Pokemon data: %v", err)
	}

	// タイプ名を初期化
	if err := loadTypeNames(); err != nil {
		log.Fatalf("Failed to initialize Pokemon type names: %v", err)
	}

	// --- Ginサーバーの設定 ---
	// Ginを本番環境向けに設定
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Logger())   // リクエストログを出力するミドルウェア
	router.Use(gin.Recovery()) // パニックから回復するミドルウェア

	// セキュリティヘッダーを追加するミドルウェア
	router.Use(securityHeadersMiddleware())

	// 環境変数からフロントエンドのURLを取得
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000" // デフォルトはローカル開発環境
	}

	// CORS (Cross-Origin Resource Sharing) の設定
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{frontendURL}, // 環境変数から取得したURLを許可
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// 信頼するプロキシを設定してセキュリティ警告を解消
	router.SetTrustedProxies([]string{"127.0.0.1"})

	// --- APIエンドポイント ---

	// 認証不要なAPIグループ
	public := router.Group("/")
	{
		public.POST("/register", handleRegister)
		public.POST("/login", handleLogin)
		public.GET("/quiz", handleGetQuiz)
		public.POST("/answer", handleAnswer)
	}

	// 認証が必要なAPIグループ
	protected := router.Group("/")
	protected.Use(authMiddleware())
	{
		protected.GET("/me", handleMe)
		protected.GET("/stats", handleGetStats)
	}

	// Renderなどのホスティング環境から提供されるポート番号を取得
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // ローカル環境など、PORTが設定されていない場合は8080をデフォルトにする
	}

	log.Printf("Starting server on :%s", port)
	router.Run(":" + port)
}

// --- ハンドラ関数 ---

func handleGetQuiz(c *gin.Context) {
	// クエリパラメータから地方とリトライオプションを取得
	region := c.DefaultQuery("region", "kanto")
	retry := c.DefaultQuery("retry", "false") == "true"

	// 「間違えた問題」モードの場合
	if retry { // このブロックを修正
		userID, exists := c.Get("userID")
		if !exists {
			// ログインしていないユーザーの場合、認証ヘッダーがないので手動でトークンを検証
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString := strings.TrimPrefix(authHeader, "Bearer ")
				claims := &jwt.RegisteredClaims{}
				token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })
				if err == nil && token.Valid {
					uid, _ := strconv.Atoi(claims.Subject)
					userID = uint(uid)
					exists = true
				}
			}
		}

		// トークンが見つからない、または無効な場合はエラー
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
			return
		}

		var stat UserStat
		// ユーザーの成績レコードを取得。なければ作成。
		db.FirstOrCreate(&stat, UserStat{UserID: userID.(uint)})

		var wrongIDs []int
		// JSON文字列をスライスにデコード
		if stat.WrongAnswers != "" {
			json.Unmarshal([]byte(stat.WrongAnswers), &wrongIDs)
		}

		if len(wrongIDs) == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "間違えた問題はありません"})
			return
		}

		// 間違えた問題リストからランダムに1つ選ぶ
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(wrongIDs))))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to select a random question"})
			return
		}
		targetID := wrongIDs[randIndex.Int64()]
		pokemon, ok := pokemonMapByID[targetID]
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ポケモンのデータが見つかりません"})
			return
		}

		// ポケモンのカテゴリに基づいて選択肢プールを決定
		optionsPool, ok := pokemonListByRegion[pokemon.Category]
		if !ok || len(optionsPool) == 0 {
			// カテゴリが見つからない、または空の場合、フォールバックとして全ポケモンリストを使う
			log.Printf("Warning: Could not find options pool for category '%s'. Falling back to all Pokemon.", pokemon.Category)
			optionsPool = make([]Pokemon, 0, len(pokemonMapByID))
			for _, p := range pokemonMapByID {
				optionsPool = append(optionsPool, p)
			}
		}
		sendQuiz(c, pokemon, optionsPool)
		return
	}

	// 通常モード
	targetPokemonList, ok := pokemonListByRegion[region]
	if !ok || len(targetPokemonList) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or empty region specified"})
		return
	}
	randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(targetPokemonList))))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to select a random pokemon"})
		return
	}
	randomPokemon := targetPokemonList[randIndex.Int64()]
	sendQuiz(c, randomPokemon, targetPokemonList)
}

func sendQuiz(c *gin.Context, pokemon Pokemon, optionsPool []Pokemon) {
	// 選択肢プールから正解のポケモンを除外した新しいスライスを作成
	filteredOptionsPool := make([]Pokemon, 0, len(optionsPool)-1)
	for _, p := range optionsPool {
		if p.ID != pokemon.ID {
			filteredOptionsPool = append(filteredOptionsPool, p)
		}
	}

	options := make([]string, 0, 4)
	options = append(options, pokemon.Name)

	// 候補からランダムに3つ選ぶ
	// crypto/randには直接Shuffleがないため、手動でシャッフルします
	for i := len(filteredOptionsPool) - 1; i > 0; i-- {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := jBig.Int64()
		filteredOptionsPool[i], filteredOptionsPool[j] = filteredOptionsPool[j], filteredOptionsPool[i]
	}
	for i := 0; i < 3 && i < len(filteredOptionsPool); i++ {
		options = append(options, filteredOptionsPool[i].Name)
	}

	// 最終的な選択肢をシャッフル
	for i := len(options) - 1; i > 0; i-- {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := jBig.Int64()
		options[i], options[j] = options[j], options[i]
	}

	c.JSON(http.StatusOK, gin.H{
		"id":      pokemon.ID,
		"stats":   pokemon.Stats,
		"options": options,
		"height":  pokemon.Height,
		"weight":  pokemon.Weight,
		"types":   pokemon.Types,
	})
}

func handleAnswer(c *gin.Context) {
	var requestBody struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	correctPokemon, ok := pokemonMapByID[requestBody.ID]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Pokemon not found"})
		return
	}

	isCorrect := requestBody.Name == correctPokemon.Name

	// 認証済みユーザーの成績を更新
	userID, exists := c.Get("userID")
	if !exists {
		// ログインしていないユーザーの場合、認証ヘッダーがないので手動でトークンを検証
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) { return jwtKey, nil })
			if err == nil && token.Valid {
				uid, _ := strconv.Atoi(claims.Subject)
				userID = uint(uid)
				exists = true
			}
		}
	}
	if exists {
		updateUserStats(db, userID.(uint), correctPokemon.ID, isCorrect)
	}

	c.JSON(http.StatusOK, gin.H{
		"isCorrect":      isCorrect,
		"correctPokemon": correctPokemon,
	})
}

// --- 認証関連のハンドラ ---

func handleRegister(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	// ユーザー名とパスワードのバリデーション
	if !isValidCredentials(req.Username) || !isValidCredentials(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password must be at least 8 characters long and contain both letters and numbers."})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := User{Username: req.Username, PasswordHash: string(hashedPassword)}
	result := db.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// ユーザー統計情報も作成
	db.Create(&UserStat{UserID: user.ID, WrongAnswers: "[]"})

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user User
	if err := db.First(&user, "username = ?", req.Username).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(TOKEN_DURATION)
	claims := &jwt.RegisteredClaims{
		Subject:   strconv.Itoa(int(user.ID)),
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func handleMe(c *gin.Context) {
	userID, _ := c.Get("userID")
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": user.ID, "username": user.Username})
}

func handleGetStats(c *gin.Context) {
	userID, _ := c.Get("userID")
	var userStat UserStat
	if err := db.First(&userStat, "user_id = ?", userID).Error; err != nil {
		// まだ成績がない場合は空の統計情報を返す
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusOK, UserStat{UserID: userID.(uint), WrongAnswers: "[]"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "Stats not found"})
		return
	}
	c.JSON(http.StatusOK, userStat)
}

// --- ミドルウェア ---

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &jwt.RegisteredClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// 署名方式が期待通りか検証
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			// エラーの種類によってログレベルを変える
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userID, err := strconv.Atoi(claims.Subject)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
			return
		}

		// トークン内のユーザーIDがDBに実際に存在するか確認
		var user User
		if err := db.First(&user, uint(userID)).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found for token"})
			return
		}

		// c.Set("userID", user.ID) // user.ID をセットする
		c.Set("userID", uint(userID)) // 既存のコードとの互換性のため、こちらを維持
		c.Next()
	}
}

// --- ヘルパー関数 ---

func updateUserStats(db *gorm.DB, userID uint, pokemonID int, isCorrect bool) {
	// トランザクションを開始
	err := db.Transaction(func(tx *gorm.DB) error {
		var stat UserStat
		// レコードをロックして取得し、なければ作成
		if err := tx.FirstOrCreate(&stat, UserStat{UserID: userID}).Error; err != nil {
			return err
		}

		stat.TotalQuestions++
		var wrongIDs []int
		if stat.WrongAnswers != "" && stat.WrongAnswers != "null" {
			if err := json.Unmarshal([]byte(stat.WrongAnswers), &wrongIDs); err != nil {
				// JSONのパースに失敗した場合、空のスライスとして扱う
				wrongIDs = []int{}
			}
		}

		if isCorrect {
			stat.TotalCorrect++
			// 間違えたリストから削除
			newWrongIDs := make([]int, 0, len(wrongIDs))
			for _, id := range wrongIDs {
				if id != pokemonID {
					newWrongIDs = append(newWrongIDs, id)
				}
			}
			wrongIDs = newWrongIDs
		} else {
			// 間違えたリストに追加（重複しないように）
			found := false
			for _, id := range wrongIDs {
				if id == pokemonID {
					found = true
					break
				}
			}
			if !found {
				wrongIDs = append(wrongIDs, pokemonID)
			}
		}

		updatedWrong, _ := json.Marshal(wrongIDs)
		stat.WrongAnswers = string(updatedWrong)

		return tx.Save(&stat).Error
	})

	if err != nil {
		log.Printf("Failed to update user stats for user %d: %v", userID, err)
	}
}

// --- ミドルウェア ---

// securityHeadersMiddleware は、推奨されるセキュリティ関連のHTTPヘッダーをすべてのレスポンスに追加します。
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// クリックジャッキング対策: ページがフレーム内に埋め込まれるのを防ぐ
		c.Header("X-Frame-Options", "DENY")
		// MIMEスニッフィング対策
		c.Header("X-Content-Type-Options", "nosniff")
		// APIなので、フレームに埋め込まれることを想定しないCSP
		c.Header("Content-Security-Policy", "frame-ancestors 'none'")
		// リファラー情報の制御
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

// isValidCredentials は、ユーザー名とパスワードが要件を満たしているか検証します。
func isValidCredentials(cred string) bool {
	if len(cred) < 8 {
		return false
	}
	hasLetter, _ := regexp.MatchString(`[a-zA-Z]`, cred)
	hasNumber, _ := regexp.MatchString(`[0-9]`, cred)
	isAlphanumeric, _ := regexp.MatchString(`^[a-zA-Z0-9]+$`, cred)

	return hasLetter && hasNumber && isAlphanumeric
}

// loadOrFetchPokemonData は、pokemon.jsonが存在すればそこからデータを読み込み、
// 存在しなければPokeAPIから取得してファイルに保存します。
func loadOrFetchPokemonData() error {
	if _, err := os.Stat(pokemonDataFile); err == nil {
		// ファイルが存在する場合
		log.Println("Loading Pokemon data from", pokemonDataFile)
		data, err := os.ReadFile(pokemonDataFile)
		if err != nil {
			return fmt.Errorf("failed to read pokemon data file: %w", err)
		}
		if err := json.Unmarshal(data, &pokemonMapByID); err != nil {
			return fmt.Errorf("failed to unmarshal pokemon data: %w", err)
		}
		log.Printf("Successfully loaded %d Pokemon from file.", len(pokemonMapByID))

		// 読み込んだデータに不足がないか確認し、あればAPIから再取得する
		// 最初のポケモンデータで判定
		if p, ok := pokemonMapByID[1]; ok && (len(p.Types) == 0 || p.Height == 0 || p.Weight == 0) {
			log.Println("Cached data is incomplete. Refetching all data from PokeAPI...")
			// マップをクリアして再取得
			pokemonMapByID = make(map[int]Pokemon)
			if err := fetchAllPokemonData(); err != nil {
				return fmt.Errorf("failed to refetch pokemon data: %w", err)
			}
			// 新しいデータでファイルを上書き
			data, err := json.MarshalIndent(pokemonMapByID, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal refetched pokemon data: %w", err)
			}
			os.WriteFile(pokemonDataFile, data, 0644) // エラーは無視（最悪次回再取得される）
		}
	} else if errors.Is(err, os.ErrNotExist) {
		// ファイルが存在しない場合
		log.Println(pokemonDataFile, "not found. Fetching from PokeAPI...")
		if err := fetchAllPokemonData(); err != nil {
			return fmt.Errorf("failed to fetch pokemon data: %w", err)
		}

		// 取得したデータをJSONファイルに保存
		data, err := json.MarshalIndent(pokemonMapByID, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal pokemon data: %w", err)
		}
		if err := os.WriteFile(pokemonDataFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write pokemon data file: %w", err)
		}
		log.Printf("Successfully fetched and saved %d Pokemon to %s", len(pokemonMapByID), pokemonDataFile)
	} else {
		// その他のエラー
		return fmt.Errorf("failed to check pokemon data file: %w", err)
	}

	// 地方別リストがまだ構築されていない場合のみ構築する
	if len(pokemonListByRegion) == 0 {
		log.Println("Building category lists...")
		buildCategoryLists()
	}

	return nil
}

// fetchAllPokemonData は、PokeAPIから指定された数のポケモンデータを並行して取得します。
func fetchAllPokemonData() error {
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 20 * time.Second} // タイムアウトを少し延長

	// タイプの日本語名を先に読み込む
	if err := loadTypeNames(); err != nil {
		return fmt.Errorf("failed to load type names: %w", err)
	}

	// 同時実行数を制限するためのセマフォ
	// Renderの無料プランなどを考慮し、同時実行数を10に制限
	semaphore := make(chan struct{}, 10)

	// 1. まず全てのポケモンの基本データを並行取得してマップに格納
	// PokeAPIの仕様上、IDは1025(Paldea) + α 程度まで存在する
	const MAX_POKEMON_ID = 1025 // 必要に応じて調整
	var mu sync.Mutex

	for i := 1; i <= MAX_POKEMON_ID; i++ {
		semaphore <- struct{}{} // セマフォを取得
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() { <-semaphore }() // このゴルーチンが終了する際に必ずセマフォを解放する

			// ポケモンの基本情報と種族値を取得
			pokemonResp, err := client.Get(fmt.Sprintf("https://pokeapi.co/api/v2/pokemon/%d", id))
			if err != nil {
				// タイムアウトなどのネットワークエラーをログに出力
				log.Printf("Error fetching pokemon %d: %v", id, err)
				return
			}
			defer pokemonResp.Body.Close()

			// レスポンスボディを一度メモリに読み込む
			body, err := io.ReadAll(pokemonResp.Body)
			if err != nil {
				log.Printf("Error reading pokemon response body %d: %v", id, err)
				return
			}

			if pokemonResp.StatusCode == http.StatusNotFound {
				return // 存在しないIDはスキップ
			}

			var apiPokemon pokeAPIPokemonResponse
			if err := json.Unmarshal(body, &apiPokemon); err != nil {
				log.Printf("Error decoding pokemon %d: %v", id, err)
				return
			}

			// ポケモンの日本語名を取得
			speciesResp, err := client.Get(fmt.Sprintf("https://pokeapi.co/api/v2/pokemon-species/%d", id))
			if err != nil {
				log.Printf("Error fetching species %d: %v", id, err)
				return
			}
			defer speciesResp.Body.Close()

			body, err = io.ReadAll(speciesResp.Body)
			if err != nil {
				log.Printf("Error reading species response body %d: %v", id, err)
				return
			}

			var apiSpecies pokeAPISpeciesResponse
			if err := json.Unmarshal(body, &apiSpecies); err != nil {
				log.Printf("Error decoding species %d: %v", id, err)
				return
			}

			// 必要な情報を抽出
			pokemon := buildPokemon(apiPokemon, apiSpecies)

			// スレッドセーフにリストとマップに追加
			mu.Lock()
			pokemonMapByID[pokemon.ID] = pokemon

			// 2. フォルム違いを特定して追加
			for _, variety := range apiSpecies.Varieties {
				if !variety.IsDefault {
					vName := variety.Pokemon.Name
					// wg.Add(1) をゴルーチン起動の前に追加
					if strings.Contains(vName, "-mega") || strings.Contains(vName, "-mega-x") || strings.Contains(vName, "-mega-y") {
						wg.Add(1)
						go fetchAndAddVariety(vName, "mega", &wg, semaphore, &mu)
					} else if strings.Contains(vName, "-gmax") {
						wg.Add(1)
						go fetchAndAddVariety(vName, "gmax", &wg, semaphore, &mu)
					} else if strings.Contains(vName, "-alola") || strings.Contains(vName, "-galar") || strings.Contains(vName, "-hisui") || strings.Contains(vName, "-paldea") {
						wg.Add(1)
						go fetchAndAddVariety(vName, "regional", &wg, semaphore, &mu)
					}
				}
			}
			mu.Unlock()

		}(i)
	}
	wg.Wait()

	return nil // 成功
}

// fetchAndAddVariety は、フォルム違いのポケモンデータを取得してマップに追加するヘルパー関数です。
func fetchAndAddVariety(name string, category string, wg *sync.WaitGroup, semaphore chan struct{}, mu *sync.Mutex) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	client := &http.Client{Timeout: 20 * time.Second}

	// 既にマップに存在するかチェック（重複追加を避ける）
	mu.Lock()
	for _, p := range pokemonMapByID {
		if p.EnglishName == name {
			mu.Unlock()
			return
		}
	}
	mu.Unlock()

	// ポケモンの基本情報と種族値を取得
	pokemonResp, err := client.Get(fmt.Sprintf("https://pokeapi.co/api/v2/pokemon/%s", name))
	if err != nil {
		log.Printf("Error fetching variety %s: %v", name, err)
		return
	}
	defer pokemonResp.Body.Close()

	if pokemonResp.StatusCode == http.StatusNotFound {
		return // 存在しない場合はスキップ
	}

	var apiPokemon pokeAPIPokemonResponse
	if err := json.NewDecoder(pokemonResp.Body).Decode(&apiPokemon); err != nil {
		log.Printf("Error decoding variety %s: %v", name, err)
		return
	}

	// ポケモンの日本語名を取得
	speciesResp, err := client.Get(apiPokemon.Species.URL)
	if err != nil {
		log.Printf("Error fetching species for variety %s: %v", name, err)
		return
	}
	defer speciesResp.Body.Close()

	var apiSpecies pokeAPISpeciesResponse
	if err := json.NewDecoder(speciesResp.Body).Decode(&apiSpecies); err != nil {
		log.Printf("Error decoding species for variety %s: %v", name, err)
		return
	}

	// 必要な情報を抽出
	pokemon := buildPokemon(apiPokemon, apiSpecies)
	pokemon.Category = category // カテゴリを上書き

	// スレッドセーフにマップに追加
	mu.Lock()
	// IDが重複しないように、10000番台をフォルム違いに割り当てる
	pokemon.ID += 10000
	pokemonMapByID[pokemon.ID] = pokemon
	mu.Unlock()
}

// loadTypeNames は、PokeAPIからタイプの日本語名を取得してマップに保存します。
func loadTypeNames() error {
	if len(typeNameMap) > 0 {
		return nil // 既に読み込み済み
	}
	log.Println("Fetching Pokemon type names...")
	client := &http.Client{Timeout: 10 * time.Second}
	// タイプは18種類 + 不明・かげ
	for i := 1; i <= 18; i++ {
		resp, err := client.Get(fmt.Sprintf("https://pokeapi.co/api/v2/type/%d", i))
		if err != nil {
			return fmt.Errorf("failed to fetch type %d: %w", i, err)
		}
		defer resp.Body.Close()

		var typeResp pokeAPITypeResponse
		if err := json.NewDecoder(resp.Body).Decode(&typeResp); err != nil {
			return fmt.Errorf("failed to decode type %d: %w", i, err)
		}

		// 英語のtype名を取得
		englishTypeName := ""
		for _, nameInfo := range typeResp.Names {
			if nameInfo.Language.Name == "en" {
				englishTypeName = nameInfo.Name
				break
			}
		}

		for _, nameInfo := range typeResp.Names {
			if nameInfo.Language.Name == "ja-Hrkt" {
				typeNameMap[englishTypeName] = nameInfo.Name
			}
		}
	}
	return nil
}

// buildRegionalLists は、pokemonMapByIDから地方ごとのリストを構築します。
func buildCategoryLists() {
	client := &http.Client{Timeout: 30 * time.Second}

	// まず、名前から特殊カテゴリを判定して設定する
	for id, p := range pokemonMapByID {
		if strings.Contains(p.EnglishName, "-mega") {
			p.Category = "mega"
		} else if strings.Contains(p.EnglishName, "-gmax") {
			p.Category = "gmax"
		} else if strings.Contains(p.EnglishName, "-alola") || strings.Contains(p.EnglishName, "-galar") || strings.Contains(p.EnglishName, "-hisui") || strings.Contains(p.EnglishName, "-paldea") {
			p.Category = "regional"
		}
		pokemonMapByID[id] = p
	}

	// 次に、地方ごとにポケモンを分類する (特殊カテゴリは上書きしない)
	for region, genID := range regionGenerationMap {
		if genID <= 0 { // 特殊カテゴリはAPIリクエストをスキップ
			continue
		}
		resp, err := client.Get(fmt.Sprintf("https://pokeapi.co/api/v2/generation/%d", genID))
		if err != nil {
			log.Printf("Error fetching generation %s: %v", region, err)
			continue
		}
		defer resp.Body.Close()

		var apiGeneration pokeAPIGenerationResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiGeneration); err != nil {
			log.Printf("Error decoding generation %s: %v", region, err)
			continue
		}

		var regionalPokemonList []Pokemon
		for _, species := range apiGeneration.PokemonSpecies {
			// species.URLからIDを抽出するロジックに修正
			// 例: "https://pokeapi.co/api/v2/pokemon-species/1/" -> "1"
			urlParts := strings.Split(strings.TrimSuffix(species.URL, "/"), "/")
			id, err := strconv.Atoi(urlParts[len(urlParts)-1])
			if err != nil {
				continue // IDが取得できなければスキップ
			}
			if p, ok := pokemonMapByID[id]; ok && p.Category == "" { // まだカテゴリが設定されていないポケモンのみ
				// カテゴリ情報を更新
				p.Category = region
				pokemonMapByID[id] = p
				regionalPokemonList = append(regionalPokemonList, p)
			}
		}
		pokemonListByRegion[region] = regionalPokemonList
		log.Printf("Region %s has %d Pokemon.", region, len(regionalPokemonList))
	}

	// 最後に、特殊カテゴリのリストを再構築
	pokemonListByRegion["mega"] = getPokemonByCategory("mega")
	pokemonListByRegion["gmax"] = getPokemonByCategory("gmax")
	pokemonListByRegion["regional"] = getPokemonByCategory("regional")
	for _, category := range []string{"mega", "gmax", "regional"} {
		log.Printf("Category %s has %d Pokemon.", category, len(pokemonListByRegion[category]))
	}
}

// buildPokemon は、APIレスポンスからPokemon構造体を組み立てます。
func buildPokemon(apiPokemon pokeAPIPokemonResponse, apiSpecies pokeAPISpeciesResponse) Pokemon {
	var stats PokemonStats
	for _, s := range apiPokemon.Stats {
		switch s.Stat.Name {
		case "hp":
			stats.HP = s.BaseStat
		case "attack":
			stats.Attack = s.BaseStat
		case "defense":
			stats.Defense = s.BaseStat
		case "special-attack":
			stats.SpAttack = s.BaseStat
		case "special-defense":
			stats.SpDefense = s.BaseStat
		case "speed":
			stats.Speed = s.BaseStat
		}
	}

	var japaneseName string
	// ja (公式の漢字名) を最優先で探す
	for _, nameInfo := range apiSpecies.Names {
		if nameInfo.Language.Name == "ja" {
			japaneseName = nameInfo.Name
			break // 見つかったらループを抜ける
		}
	}

	// ja が見つからなかった場合のみ、ja-Hrkt (ひらがな・カタカナ) を探す
	if japaneseName == "" {
		for _, nameInfo := range apiSpecies.Names {
			if nameInfo.Language.Name == "ja-Hrkt" {
				japaneseName = nameInfo.Name
				break
			}
		}
	}
	if japaneseName == "" {
		japaneseName = apiPokemon.Name // 日本語名がなければ英語名を使う
	}

	// タイプの日本語名を取得
	var japaneseTypes []string
	for _, typeInfo := range apiPokemon.Types {
		typeID := typeInfo.Type.Name // 英語名でマップを引く
		if name, ok := typeNameMap[typeID]; ok {
			japaneseTypes = append(japaneseTypes, name)
		}
	}

	return Pokemon{
		ID:          apiPokemon.ID,
		Name:        japaneseName,
		EnglishName: apiPokemon.Name, // 英語名を構造体にセット
		Stats:       stats,
		ImageURL:    apiPokemon.Sprites.Other.OfficialArtwork.FrontDefault,
		Height:      apiPokemon.Height / 10.0, // デシメートルからメートルに変換
		Weight:      apiPokemon.Weight / 10.0, // ヘクトグラムからキログラムに変換
		Types:       japaneseTypes,
	}
}

// getPokemonByCategory は、指定されたカテゴリのポケモンリストを返します。
func getPokemonByCategory(category string) []Pokemon {
	var list []Pokemon
	for _, p := range pokemonMapByID {
		if p.Category == category {
			list = append(list, p)
		}
	}
	return list
}

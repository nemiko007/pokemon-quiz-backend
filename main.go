package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite" // CGO不要のドライバに変更
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// --- 構造体の定義 ---

// クライアントに返すポケモンの情報
type Pokemon struct {
	ID          int          `json:"id"`
	Name        string       `json:"name"` // 日本語名
	EnglishName string       `json:"-"`    // 英語名 (JSONには含めない)
	Stats       PokemonStats `json:"stats"`
	ImageURL    string       `json:"imageUrl"`
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
}

// /pokemon-species/{id} のレスポンス
type pokeAPISpeciesResponse struct {
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

// 地方名とPokeAPIの世代IDの対応表
var regionGenerationMap = map[string]int{
	"kanto":  1,
	"johto":  2,
	"hoenn":  3,
	"sinnoh": 4,
	"unova":  5,
	"kalos":  6,
	"alola":  7,
	"galar":  8,
	"paldea": 9,
}

func main() {
	// .envファイルから環境変数を読み込む（ファイルが存在しなくてもエラーにはならない）
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Could not load .env file. Reading environment variables from OS.")
	}

	jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(jwtKey) == 0 {
		// JWTキーが設定されていない場合は、安全でないためプログラムを終了する
		log.Fatal("FATAL: JWT_SECRET_KEY environment variable is not set.")
	}

	// データベースの初期化
	db, err = gorm.Open(sqlite.Open("pokemon_quiz.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db.AutoMigrate(&User{}, &UserStat{}) // テーブルを自動生成

	// サーバー起動時に一度だけ全ポケモンのデータを取得する
	log.Println("Fetching Pokemon data from PokeAPI...")
	if err := fetchAllPokemonData(); err != nil {
		log.Fatalf("Failed to fetch pokemon data: %v", err)
	}
	log.Printf("Successfully fetched %d Pokemon.", len(pokemonMapByID))

	// Ginを本番環境向けに設定
	gin.SetMode(gin.ReleaseMode)

	// gin.Default()の代わりにgin.New()を使い、ミドルウェアを明示的に指定
	router := gin.New()
	router.Use(gin.Logger())   // リクエストログを出力するミドルウェア
	router.Use(gin.Recovery()) // パニックから回復するミドルウェア

	// CORS (Cross-Origin Resource Sharing) の設定
	// Reactアプリ(デフォルトではlocalhost:3000)からのリクエストを許可する
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// 信頼するプロキシを設定してセキュリティ警告を解消
	// ローカル環境ではこれで問題ありません
	router.SetTrustedProxies([]string{"127.0.0.1"})

	// --- APIエンドポイント ---

	// 認証不要なAPIグループ
	public := router.Group("/")
	{
		public.POST("/register", handleRegister)
		public.POST("/login", handleLogin)
	}

	// 認証が必要なAPIグループ
	protected := router.Group("/")
	protected.Use(authMiddleware())
	{
		protected.GET("/me", handleMe)
		protected.GET("/stats", handleGetStats)
		protected.GET("/quiz", handleGetQuiz)
		protected.POST("/answer", handleAnswer)
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
	if retry {
		userID, exists := c.Get("userID")
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
		rand.Seed(time.Now().UnixNano())
		targetID := wrongIDs[rand.Intn(len(wrongIDs))]
		pokemon, ok := pokemonMapByID[targetID]
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ポケモンのデータが見つかりません"})
			return
		}

		// 選択肢はカントー地方のポケモンから生成する（どの地方の問題でも選択肢のプールは同じにする）
		sendQuiz(c, pokemon, pokemonListByRegion["kanto"])
		return
	}

	// 通常モード
	targetPokemonList, ok := pokemonListByRegion[region]
	if !ok || len(targetPokemonList) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or empty region specified"})
		return
	}
	rand.Seed(time.Now().UnixNano())
	randomPokemon := targetPokemonList[rand.Intn(len(targetPokemonList))]
	sendQuiz(c, randomPokemon, targetPokemonList)
}

func sendQuiz(c *gin.Context, pokemon Pokemon, optionsPool []Pokemon) {
	options := make([]string, 0, 4)
	options = append(options, pokemon.Name)

	usedNames := make(map[string]bool)
	usedNames[pokemon.Name] = true

	for len(options) < 4 && len(optionsPool) > len(options) {
		distractor := optionsPool[rand.Intn(len(optionsPool))]
		if !usedNames[distractor.Name] {
			options = append(options, distractor.Name)
			usedNames[distractor.Name] = true
		}
	}

	rand.Shuffle(len(options), func(i, j int) {
		options[i], options[j] = options[j], options[i]
	})

	c.JSON(http.StatusOK, gin.H{
		"id":      pokemon.ID,
		"stats":   pokemon.Stats,
		"options": options,
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
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userID, err := strconv.Atoi(claims.Subject)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
			return
		}

		c.Set("userID", uint(userID))
		c.Next()
	}
}

// --- ヘルパー関数 ---

func updateUserStats(db *gorm.DB, userID uint, pokemonID int, isCorrect bool) {
	var stat UserStat
	// レコードが存在しない場合に備えてFirstOrCreateを使用
	if err := db.FirstOrCreate(&stat, UserStat{UserID: userID}).Error; err != nil {
		return // エラーハンドリング
	}

	stat.TotalQuestions++
	var wrongIDs []int
	if stat.WrongAnswers != "" {
		json.Unmarshal([]byte(stat.WrongAnswers), &wrongIDs)
	}

	if isCorrect {
		stat.TotalCorrect++
		// 間違えたリストから削除
		newWrongIDs := []int{}
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

	db.Save(&stat)
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

// fetchAllPokemonData は、PokeAPIから指定された数のポケモンデータを並行して取得します。
func fetchAllPokemonData() error {
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}

	// 1. まず全てのポケモンの基本データを並行取得してマップに格納
	// PokeAPIの仕様上、IDは1025(Paldea) + α 程度まで存在する
	const MAX_POKEMON_ID = 1025 // 必要に応じて調整
	var pokemonTempMap = make(map[int]Pokemon)
	var mu sync.Mutex

	for i := 1; i <= MAX_POKEMON_ID; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// ポケモンの基本情報と種族値を取得
			pokemonResp, err := client.Get(fmt.Sprintf("https://pokeapi.co/api/v2/pokemon/%d", id))
			if err != nil {
				if err, ok := err.(*os.PathError); !ok || !errors.Is(err.Err, os.ErrNotExist) {
					log.Printf("Error fetching pokemon %d: %v", id, err)
				}
				return
			}
			defer pokemonResp.Body.Close()
			if pokemonResp.StatusCode == http.StatusNotFound {
				return // 存在しないIDはスキップ
			}

			var apiPokemon pokeAPIPokemonResponse
			if err := json.NewDecoder(pokemonResp.Body).Decode(&apiPokemon); err != nil {
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

			var apiSpecies pokeAPISpeciesResponse
			if err := json.NewDecoder(speciesResp.Body).Decode(&apiSpecies); err != nil {
				log.Printf("Error decoding species %d: %v", id, err)
				return
			}

			// 必要な情報を抽出
			pokemon := buildPokemon(apiPokemon, apiSpecies)

			// スレッドセーフにリストとマップに追加
			mu.Lock()
			pokemonMapByID[pokemon.ID] = pokemon
			pokemonTempMap[pokemon.ID] = pokemon
			mu.Unlock()

		}(i)
	}
	wg.Wait() // 全てのgoroutineが完了するのを待つ

	// 地方ごとにポケモンを分類する
	for region, genID := range regionGenerationMap {
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
			urlParts := strings.Split(strings.TrimSuffix(species.Name, "/"), "/")
			id, err := strconv.Atoi(urlParts[len(urlParts)-1])
			if err != nil {
				// species.NameがIDでない場合（名前の場合）のフォールバック
				for _, p := range pokemonMapByID {
					if p.EnglishName == species.Name {
						id = p.ID
						break
					}
				}
				if id == 0 {
					continue
				}
			}
			if p, ok := pokemonMapByID[id]; ok {
				regionalPokemonList = append(regionalPokemonList, p)
			}
		}
		pokemonListByRegion[region] = regionalPokemonList
		log.Printf("Region %s has %d Pokemon.", region, len(regionalPokemonList))
	}

	return nil
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
	for _, nameInfo := range apiSpecies.Names {
		if nameInfo.Language.Name == "ja-Hrkt" { // ひらがな・カタカナの日本語名
			japaneseName = nameInfo.Name
			break
		}
	}
	if japaneseName == "" {
		japaneseName = apiPokemon.Name // 日本語名がなければ英語名を使う
	}

	return Pokemon{
		ID:          apiPokemon.ID,
		Name:        japaneseName,
		EnglishName: apiPokemon.Name, // 英語名を構造体にセット
		Stats:       stats,
		ImageURL:    apiPokemon.Sprites.Other.OfficialArtwork.FrontDefault,
	}
}

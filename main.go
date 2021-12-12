package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/380566067/eth-pool/api"
	"github.com/380566067/eth-pool/payouts"
	"github.com/380566067/eth-pool/proxy"
	"github.com/380566067/eth-pool/storage"
)

var cfg proxy.Config
var backend *storage.RedisClient

func startProxy() {
	s := proxy.NewProxy(&cfg, backend)
	s.Start()
}

func startApi() {
	s := api.NewApiServer(&cfg.Api, backend)
	s.Start()
}

func startBlockUnlocker() {
	u := payouts.NewBlockUnlocker(&cfg.BlockUnlocker, backend)
	u.Start()
}

func startPayoutsProcessor() {
	u := payouts.NewPayoutsProcessor(&cfg.Payouts, backend)
	u.Start()
}

func readConfig(cfg *proxy.Config) {
	configFileName := "config.json"
	if len(os.Args) > 1 {
		configFileName = os.Args[1]
	}
	configFileName, _ = filepath.Abs(configFileName)
	log.Printf("载入配置文件: %v", configFileName)

	configFile, err := os.Open(configFileName)
	if err != nil {
		log.Fatal("配置文件读取失败,错误: ", err.Error())
	}
	defer configFile.Close()
	jsonParser := json.NewDecoder(configFile)
	if err := jsonParser.Decode(&cfg); err != nil {
		log.Fatal("配置文件设置有误,错误: ", err.Error())
	}
}

func main() {
	readConfig(&cfg)
	rand.Seed(time.Now().UnixNano())

	if cfg.Threads > 0 {
		runtime.GOMAXPROCS(cfg.Threads)
		log.Printf("程序已启动,线程数量: %v", cfg.Threads)
	}

	backend = storage.NewRedisClient(&cfg.Redis, cfg.Coin)
	pong, err := backend.Check()
	if err != nil {
		log.Printf("数据库连接失败,错误: %v", err)
	} else {
		log.Printf("数据库连接成功,反馈: %v", pong)
	}

	if cfg.Proxy.Enabled {
		go startProxy()
	}
	if cfg.Api.Enabled {
		go startApi()
	}
	if cfg.BlockUnlocker.Enabled {
		go startBlockUnlocker()
	}
	if cfg.Payouts.Enabled {
		go startPayoutsProcessor()
	}
	quit := make(chan bool)
	<-quit
}

package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"

	"github.com/380566067/eth-pool/storage"
	"github.com/380566067/eth-pool/util"
)

type ApiConfig struct {
	Enabled              bool   `json:"enabled"`
	Listen               string `json:"listen"`
	StatsCollectInterval string `json:"statsCollectInterval"`
	HashrateWindow       string `json:"hashrateWindow"`
	HashrateLargeWindow  string `json:"hashrateLargeWindow"`
	LuckWindow           []int  `json:"luckWindow"`
	Payments             int64  `json:"payments"`
	Blocks               int64  `json:"blocks"`
	PurgeOnly            bool   `json:"purgeOnly"`
	PurgeInterval        string `json:"purgeInterval"`
}

type ApiServer struct {
	config              *ApiConfig
	backend             *storage.RedisClient
	hashrateWindow      time.Duration
	hashrateLargeWindow time.Duration
	stats               atomic.Value
	miners              map[string]*Entry
	minersMu            sync.RWMutex
	statsIntv           time.Duration
}

type Entry struct {
	stats     map[string]interface{}
	updatedAt int64
}

func NewApiServer(cfg *ApiConfig, backend *storage.RedisClient) *ApiServer {
	hashrateWindow := util.MustParseDuration(cfg.HashrateWindow)
	hashrateLargeWindow := util.MustParseDuration(cfg.HashrateLargeWindow)
	return &ApiServer{
		config:              cfg,
		backend:             backend,
		hashrateWindow:      hashrateWindow,
		hashrateLargeWindow: hashrateLargeWindow,
		miners:              make(map[string]*Entry),
	}
}

func (s *ApiServer) Start() {
	if s.config.PurgeOnly {
		log.Printf("Starting API in purge-only mode")
	} else {
		log.Printf("启动API接口,侦听: %v", s.config.Listen)
	}

	s.statsIntv = util.MustParseDuration(s.config.StatsCollectInterval)
	statsTimer := time.NewTimer(s.statsIntv)
	log.Printf("设置统计数据生成周期: %v", s.statsIntv)

	purgeIntv := util.MustParseDuration(s.config.PurgeInterval)
	purgeTimer := time.NewTimer(purgeIntv)
	log.Printf("设置统计数据复位周期: %v", purgeIntv)

	sort.Ints(s.config.LuckWindow)

	if s.config.PurgeOnly {
		s.purgeStale()
	} else {
		s.purgeStale()
		s.collectStats()
	}

	go func() {
		for {
			select {
			case <-statsTimer.C:
				if !s.config.PurgeOnly {
					s.collectStats()
				}
				statsTimer.Reset(s.statsIntv)
			case <-purgeTimer.C:
				s.purgeStale()
				purgeTimer.Reset(purgeIntv)
			}
		}
	}()

	if !s.config.PurgeOnly {
		s.listen()
	}
}

func (s *ApiServer) listen() {
	r := mux.NewRouter()
	r.HandleFunc("/api/stats", s.StatsIndex)
	r.HandleFunc("/api/miners", s.MinersIndex)
	r.HandleFunc("/api/blocks", s.BlocksIndex)
	r.HandleFunc("/api/payments", s.PaymentsIndex)
	r.HandleFunc("/api/accounts/{login:0x[0-9a-fA-F]{40}}", s.AccountIndex)
	r.NotFoundHandler = http.HandlerFunc(notFound)
	err := http.ListenAndServe(s.config.Listen, r)
	if err != nil {
		log.Fatalf("启动API接口侦听失败,详情: %v", err)
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusNotFound)
}

func (s *ApiServer) purgeStale() {
	start := time.Now()
	total, err := s.backend.FlushStaleStats(s.hashrateWindow, s.hashrateLargeWindow)
	if err != nil {
		log.Println("复位统计数据失败,详情: %v", err)
	} else {
		log.Printf("复位统计数据, 共计: %v shares, 用时: %v", total, time.Since(start))
	}
}

func (s *ApiServer) collectStats() {
	//start := time.Now()
	stats, err := s.backend.CollectStats(s.hashrateWindow, s.config.Blocks, s.config.Payments)
	if err != nil {
		log.Printf("获取统计数据失败,详情: %v", err)
		return
	}
	if len(s.config.LuckWindow) > 0 {
		stats["luck"], err = s.backend.CollectLuckStats(s.config.LuckWindow)
		if err != nil {
			log.Printf("获取'幸运值'失败,详情: %v", err)
			return
		}
	}
	s.stats.Store(stats)
	//log.Printf("获取统计数据成功,用时: %s", time.Since(start))
}

func (s *ApiServer) StatsIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	reply := make(map[string]interface{})
	nodes, err := s.backend.GetNodeStates()
	if err != nil {
		log.Printf("获取矿池统计数据失败,详情: %v", err)
	}
	reply["nodes"] = nodes

	stats := s.getStats()
	if stats != nil {
		reply["now"] = util.MakeTimestamp()
		reply["stats"] = stats["stats"]
		reply["hashrate"] = stats["hashrate"]
		reply["minersTotal"] = stats["minersTotal"]
		reply["maturedTotal"] = stats["maturedTotal"]
		reply["immatureTotal"] = stats["immatureTotal"]
		reply["candidatesTotal"] = stats["candidatesTotal"]
	}

	err = json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("数据解码失败,详情: %v", err)
	}
}

func (s *ApiServer) MinersIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	reply := make(map[string]interface{})
	stats := s.getStats()
	if stats != nil {
		reply["now"] = util.MakeTimestamp()
		reply["miners"] = stats["miners"]
		reply["hashrate"] = stats["hashrate"]
		reply["minersTotal"] = stats["minersTotal"]
	}

	err := json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("数据解码失败,详情: %v", err)
	}
}

func (s *ApiServer) BlocksIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	reply := make(map[string]interface{})
	stats := s.getStats()
	if stats != nil {
		reply["matured"] = stats["matured"]
		reply["maturedTotal"] = stats["maturedTotal"]
		reply["immature"] = stats["immature"]
		reply["immatureTotal"] = stats["immatureTotal"]
		reply["candidates"] = stats["candidates"]
		reply["candidatesTotal"] = stats["candidatesTotal"]
		reply["luck"] = stats["luck"]
	}

	err := json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("数据解码失败,详情: %v", err)
	}
}

func (s *ApiServer) PaymentsIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	reply := make(map[string]interface{})
	stats := s.getStats()
	if stats != nil {
		reply["payments"] = stats["payments"]
		reply["paymentsTotal"] = stats["paymentsTotal"]
	}

	err := json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("数据解码失败,详情: %v", err)
	}
}

func (s *ApiServer) AccountIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")

	login := strings.ToLower(mux.Vars(r)["login"])
	s.minersMu.Lock()
	defer s.minersMu.Unlock()

	reply, ok := s.miners[login]
	now := util.MakeTimestamp()
	cacheIntv := int64(s.statsIntv / time.Millisecond)
	// Refresh stats if stale
	if !ok || reply.updatedAt < now-cacheIntv {
		exist, err := s.backend.IsMinerExists(login)
		if !exist {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("获取统计数据失败,详情: %v", err)
			return
		}

		stats, err := s.backend.GetMinerStats(login, s.config.Payments)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("获取统计数据失败,详情: %v", err)
			return
		}
		workers, err := s.backend.CollectWorkersStats(s.hashrateWindow, s.hashrateLargeWindow, login)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("获取统计数据失败,详情: %v", err)
			return
		}
		for key, value := range workers {
			stats[key] = value
		}
		stats["pageSize"] = s.config.Payments
		reply = &Entry{stats: stats, updatedAt: now}
		s.miners[login] = reply
	}

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(reply.stats)
	if err != nil {
		log.Println("数据解码失败,详情: %v", err)
	}
}

func (s *ApiServer) getStats() map[string]interface{} {
	stats := s.stats.Load()
	if stats != nil {
		return stats.(map[string]interface{})
	}
	return nil
}

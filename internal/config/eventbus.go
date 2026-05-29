package config

import "time"

// NATS contains all NATS / JetStream connection settings.
type NATS struct {
	URL                  string
	Name                 string
	User                 string
	Password             string
	Token                string
	CredsFile            string
	TLSCAFile            string
	TLSCertFile          string
	TLSKeyFile           string
	TLSInsecure          bool
	ReconnectWait        time.Duration
	MaxReconnects        int
	RequestTimeout       time.Duration
	PublishRetryAttempts int
	PublishRetryDelay    time.Duration
	DedupWindow          time.Duration
	Replicas             int
	Storage              string // "file" or "memory"
	FetchBatchSize       int
	FetchMaxWait         time.Duration
}

func loadNATS() NATS {
	return NATS{
		URL:                  getStr("NATS_URL", "nats://127.0.0.1:4222"),
		Name:                 getStr("NATS_NAME", "sn360-es"),
		User:                 getStr("NATS_USER", ""),
		Password:             getStr("NATS_PASSWORD", ""),
		Token:                getStr("NATS_TOKEN", ""),
		CredsFile:            getStr("NATS_CREDS_FILE", ""),
		TLSCAFile:            getStr("NATS_TLS_CA", ""),
		TLSCertFile:          getStr("NATS_TLS_CERT", ""),
		TLSKeyFile:           getStr("NATS_TLS_KEY", ""),
		TLSInsecure:          getBool("NATS_TLS_INSECURE", false),
		ReconnectWait:        getDuration("NATS_RECONNECT_WAIT", 2*time.Second),
		MaxReconnects:        getInt("NATS_MAX_RECONNECTS", -1),
		RequestTimeout:       getDuration("NATS_REQUEST_TIMEOUT", 5*time.Second),
		PublishRetryAttempts: getInt("NATS_PUBLISH_RETRY_ATTEMPTS", 3),
		PublishRetryDelay:    getDuration("NATS_PUBLISH_RETRY_DELAY", 200*time.Millisecond),
		DedupWindow:          getDuration("NATS_DEDUP_WINDOW", 2*time.Minute),
		Replicas:             getInt("NATS_REPLICAS", 1),
		Storage:              getStr("NATS_STORAGE", "file"),
		FetchBatchSize:       getInt("NATS_FETCH_BATCH_SIZE", 50),
		FetchMaxWait:         getDuration("NATS_FETCH_MAX_WAIT", 200*time.Millisecond),
	}
}

// Redis carries Redis client + optional event-bus config.
type Redis struct {
	Addr             string
	Password         string
	DB               int
	PoolSize         int
	MinIdleConns     int
	DialTimeout      time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	ReconnectTimeout time.Duration
	MinRetryBackoff  time.Duration
	ConsumerBlock    time.Duration
	// FetchBatchSize is the default XREADGROUP COUNT used when the
	// Redis backend is the event-bus implementation. Has no effect
	// when EVENT_BUS_TYPE=nats.
	FetchBatchSize int
}

func loadRedis() Redis {
	return Redis{
		Addr:             getStr("REDIS_ADDR", "127.0.0.1:6379"),
		Password:         getStr("REDIS_PASSWORD", ""),
		DB:               getInt("REDIS_DB", 0),
		PoolSize:         getInt("REDIS_POOL_SIZE", 20),
		MinIdleConns:     getInt("REDIS_MIN_IDLE_CONNS", 4),
		DialTimeout:      getDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
		ReadTimeout:      getDuration("REDIS_READ_TIMEOUT", 2*time.Second),
		WriteTimeout:     getDuration("REDIS_WRITE_TIMEOUT", 2*time.Second),
		ReconnectTimeout: getDuration("REDIS_RECONNECT_TIMEOUT", 30*time.Second),
		MinRetryBackoff:  getDuration("REDIS_MIN_RETRY_BACKOFF", 100*time.Millisecond),
		ConsumerBlock:    getDuration("REDIS_CONSUMER_BLOCK", 0),
		FetchBatchSize:   getInt("REDIS_FETCH_BATCH_SIZE", 10),
	}
}

package controller

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"genwaf/internal/config"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client *redis.Client
	prefix string
}

func newRedisStore(cfg config.StorageConfig) (*RedisStore, error) {
	if !cfg.RedisEnabled {
		return nil, nil
	}
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddress,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return &RedisStore{
		client: client,
		prefix: cfg.RedisPrefix,
	}, nil
}

func (r *RedisStore) Close() error {
	if r == nil || r.client == nil {
		return nil
	}
	return r.client.Close()
}

func (r *RedisStore) RecordObservation(now time.Time, batchNode string, obs ClientObservation, ttlSeconds int) (ObservationAggregate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	obsKey := r.prefix + ":obs:" + obs.ClientIP
	repKey := r.prefix + ":rep:" + obs.ClientIP
	repDelta := int64(obs.Requests + obs.ChallengeFailures*10 + obs.SensitiveHits*5)

	pipe := r.client.TxPipeline()
	pipe.HIncrBy(ctx, obsKey, "requests", int64(obs.Requests))
	pipe.HIncrBy(ctx, obsKey, "challenge_failures", int64(obs.ChallengeFailures))
	pipe.HIncrBy(ctx, obsKey, "sensitive_hits", int64(obs.SensitiveHits))
	pipe.HSet(ctx, obsKey, "last_node_id", defaultString(obs.NodeID, batchNode))
	pipe.HSet(ctx, obsKey, "updated_at", now.Format(time.RFC3339))
	pipe.Expire(ctx, obsKey, time.Duration(ttlSeconds)*time.Second)
	pipe.IncrBy(ctx, repKey, repDelta)
	pipe.Expire(ctx, repKey, time.Duration(ttlSeconds*4)*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		return ObservationAggregate{}, err
	}

	values, err := r.client.HGetAll(ctx, obsKey).Result()
	if err != nil {
		return ObservationAggregate{}, err
	}
	repValue, err := r.client.Get(ctx, repKey).Result()
	if err != nil && err != redis.Nil {
		return ObservationAggregate{}, err
	}

	requests, _ := strconv.Atoi(values["requests"])
	challengeFailures, _ := strconv.Atoi(values["challenge_failures"])
	sensitiveHits, _ := strconv.Atoi(values["sensitive_hits"])
	reputationScore, _ := strconv.Atoi(repValue)
	updatedAt, _ := time.Parse(time.RFC3339, values["updated_at"])
	if updatedAt.IsZero() {
		updatedAt = now
	}

	return ObservationAggregate{
		ClientIP:          obs.ClientIP,
		Requests:          requests,
		ChallengeFailures: challengeFailures,
		SensitiveHits:     sensitiveHits,
		LastNodeID:        values["last_node_id"],
		UpdatedAt:         updatedAt,
		ExpiresAt:         now.Add(time.Duration(ttlSeconds) * time.Second),
		ReputationScore:   reputationScore,
	}, nil
}

package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"work-v/internal/master/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecretMu  sync.RWMutex
	jwtSecretKey []byte
	tokenIssuer  = "work-v-master"
)

// SetJWTSecret 设置自定义 JWT 密钥
func SetJWTSecret(secret string) {
	if secret != "" {
		jwtSecretMu.Lock()
		jwtSecretKey = []byte(secret)
		jwtSecretMu.Unlock()
	}
}

func getJWTSecretKey() []byte {
	jwtSecretMu.RLock()
	if len(jwtSecretKey) > 0 {
		k := jwtSecretKey
		jwtSecretMu.RUnlock()
		return k
	}
	jwtSecretMu.RUnlock()

	if envSecret := os.Getenv("WORKV_JWT_SECRET"); envSecret != "" {
		SetJWTSecret(envSecret)
		return []byte(envSecret)
	}

	dbSecret := model.GetSetting("jwt_secret", "")
	if dbSecret != "" {
		SetJWTSecret(dbSecret)
		return []byte(dbSecret)
	}

	fallback := "workv_dynamic_" + fmt.Sprintf("%d", time.Now().UnixNano())
	SetJWTSecret(fallback)
	return []byte(fallback)
}

// Claims 自定义 JWT 声明
type Claims struct {
	AdminID  uint   `json:"admin_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateToken 生成管理员 JWT
func GenerateToken(adminID uint, username string, expireDuration time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		AdminID:  adminID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expireDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tokenIssuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getJWTSecretKey())
}

// ParseToken 解析并校验 JWT
func ParseToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return getJWTSecretKey(), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// AdminAuthRequired 管理员鉴权中间件
func AdminAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// 也支持从 Cookie 中读取 token (增强 Web 体验)
			cookieToken, err := c.Cookie("workv_token")
			if err == nil && cookieToken != "" {
				authHeader = "Bearer " + cookieToken
			}
		}

		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证凭据，请先登录"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "认证格式有误 (Bearer <token>)"})
			c.Abort()
			return
		}

		claims, err := ParseToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "登录凭证已过期或无效，请重新登录"})
			c.Abort()
			return
		}

		c.Set("admin_id", claims.AdminID)
		c.Set("admin_username", claims.Username)
		c.Next()
	}
}

// RateLimiter 防暴力破解与接口限流
type LoginLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

var GlobalLoginLimiter = &LoginLimiter{
	attempts: make(map[string][]time.Time),
}

// CheckAllowed 检查 IP 是否被短时间封锁 (5分钟内超过5次失败即锁定)
func (l *LoginLimiter) CheckAllowed(ip string) (bool, int) {
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)

	// 清理 5 分钟前历史记录
	valid := make([]time.Time, 0)
	for _, t := range l.attempts[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	l.attempts[ip] = valid

	if len(valid) >= 5 {
		remainingSec := int(5*60 - now.Sub(valid[0]).Seconds())
		if remainingSec < 0 {
			remainingSec = 0
		}
		return false, remainingSec
	}
	return true, 0
}

// RecordFailure 记录一次登录失败
func (l *LoginLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts[ip] = append(l.attempts[ip], time.Now())
}

// ResetSuccess 登录成功后清理失败记录
func (l *LoginLimiter) ResetSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

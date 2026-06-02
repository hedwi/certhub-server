package routes

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/controllers"
	"github.com/hedwi/certhub-server/middleware"
)

func parseSameSite(value string) http.SameSite {
	switch value {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func SetupRouter() *gin.Engine {
	r := gin.Default()
	r.Use(middleware.RateLimitMiddleware())

	s := config.Cfg.Session
	store := cookie.NewStore([]byte(s.Secret))
	store.Options(sessions.Options{
		MaxAge:   s.MaxAge,
		Path:     s.Path,
		HttpOnly: s.HttpOnly,
		Secure:   s.Secure,
		SameSite: parseSameSite(s.SameSite),
	})
	r.Use(sessions.Sessions(s.Name, store))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := r.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", controllers.Register)
			auth.POST("/login", controllers.Login)
			auth.POST("/logout", controllers.Logout)
		}

		protected := api.Group("/")
		protected.Use(middleware.AuthMiddleware())
		{
			protected.GET("/profile", controllers.GetProfile)

			domains := protected.Group("/domains")
			{
				domains.POST("", controllers.AddDomain)
				domains.GET("", controllers.ListDomains)
				domains.GET("/:id", controllers.GetDomain)
				domains.POST("/:id/verify", controllers.VerifyDomain)
				domains.DELETE("/:id", controllers.DeleteDomain)
			}

			certs := protected.Group("/certificates")
			{
				certs.POST("/generate", controllers.GenerateCertificate)
				certs.POST("/renew", controllers.RenewCertificate)
				certs.GET("", controllers.ListCertificates)
				certs.GET("/:id/download", controllers.DownloadCertificate)
			}
		}
	}

	return r
}

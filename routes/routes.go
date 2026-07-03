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
	r.Use(middleware.CORSMiddleware())

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
				domains.DELETE("/:id", controllers.DeleteDomain)

				domains.GET("/:id/cname", controllers.GetCname)
				domains.PUT("/:id/cname", controllers.UpdateCname)
				domains.POST("/:id/cname/verify", controllers.VerifyCname)

				domains.POST("/:id/certificate/issue", controllers.IssueCertificate)
				domains.GET("/:id/certificate", controllers.GetCertificateInfo)
				domains.GET("/:id/certificate/download", controllers.DownloadDomainCertificate)

				domains.GET("/:id/deploy/targets", controllers.ListDeployTargets)
				domains.POST("/:id/deploy/targets", controllers.AddDeployTarget)
				domains.PUT("/:id/deploy/targets/:targetId", controllers.UpdateDeployTarget)
				domains.DELETE("/:id/deploy/targets/:targetId", controllers.DeleteDeployTarget)
				domains.POST("/:id/deploy", controllers.DeployDomain)
				domains.GET("/:id/deploy/jobs/:jobId", controllers.GetDeployJob)
			}

			// Legacy certificate routes for direct API clients
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

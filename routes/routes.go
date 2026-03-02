package routes

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/controllers"
	"github.com/hedwi/certhub-server/middleware"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()

	// Configure session middleware from config
	s := config.Cfg.Session
	store := cookie.NewStore([]byte(s.Secret))
	store.Options(sessions.Options{
		MaxAge:   s.MaxAge,
		Path:     s.Path,
		HttpOnly: s.HttpOnly,
		Secure:   s.Secure,
	})
	r.Use(sessions.Sessions(s.Name, store))

	// CORS middleware could be added here

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

			// Routes for domains
			domains := protected.Group("/domains")
			{
				domains.POST("", controllers.AddDomain)
				domains.GET("", controllers.ListDomains)
				domains.GET("/:id", controllers.GetDomain)
				domains.DELETE("/:id", controllers.DeleteDomain)
			}

			// Routes for certificates
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

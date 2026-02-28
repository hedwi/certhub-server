package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub/controllers"
	"github.com/hedwi/certhub/middleware"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()

	// CORS middleware could be added here

	api := r.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", controllers.Register)
			auth.POST("/login", controllers.Login)
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

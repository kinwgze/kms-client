package main

import (
	"github.com/gin-gonic/gin"
	"kmip-client/pkg"
	"net/http"
)

func main() {
	router := gin.Default()
	router.GET("create", createKey)
	router.GET("query", getKeyInfo)
	router.GET("destroy", destroyKey)

	router.Run(":15696")
}

func createKey(c *gin.Context) {
	queryParams := c.Request.URL.Query()
	endPoint := queryParams.Get("endPoint")
	caFile := queryParams.Get("caFile")
	cerFile := queryParams.Get("cerFile")
	keyFile := queryParams.Get("keyFile")

	response := kmipservice.Create(endPoint, caFile, cerFile, keyFile)
	c.IndentedJSON(http.StatusOK, response)
}

func getKeyInfo(c *gin.Context) {
	queryParams := c.Request.URL.Query()
	endPoint := queryParams.Get("endPoint")
	caFile := queryParams.Get("caFile")
	cerFile := queryParams.Get("cerFile")
	keyFile := queryParams.Get("keyFile")
	uuid := queryParams.Get("uuid")

	response := kmipservice.GetKeyInfo(endPoint, caFile, cerFile, keyFile, uuid)
	c.IndentedJSON(http.StatusOK, response.SymmetricKey.KeyBlock.Value.KeyMaterial)
}

func destroyKey(c *gin.Context) {
	queryParams := c.Request.URL.Query()
	endPoint := queryParams.Get("endPoint")
	caFile := queryParams.Get("caFile")
	cerFile := queryParams.Get("cerFile")
	keyFile := queryParams.Get("keyFile")
	uuid := queryParams.Get("uuid")

	response := kmipservice.DestroyKey(endPoint, caFile, cerFile, keyFile, uuid)
	c.IndentedJSON(http.StatusOK, response.UniqueIdentifier)
}

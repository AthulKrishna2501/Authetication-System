package neo4j

import (
	"context"
	"os"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func InitNeo4J() (neo4j.DriverWithContext, error) {
	ctx := context.Background()
	dbUri := os.Getenv("NEO_URI")
	dbUser := os.Getenv("NEO_USERNAME")
	dbPassword := os.Getenv("NEO_PASSWORD")
	driver, err := neo4j.NewDriverWithContext(
		dbUri,
		neo4j.BasicAuth(dbUser, dbPassword, ""))
	if err != nil {
		panic(err)
	}
	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		panic(err)
	}

	return driver, nil
}

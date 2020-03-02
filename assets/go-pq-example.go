//This example uses the ORM jet
package main

import (
	"log"
	"os"

	"github.com/eaigner/jet"
	"github.com/lib/pq"
)

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func testMain() {
	//Make sure you setup the ELEPHANTSQL_URL to be a uri, e.g. 'postgres://user:pass@host/db?options'
	pgURL, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))
	logFatal(err)
	db, err := jet.Open("postgres", pgURL)
	logFatal(err)
	var people []*struct {
		ID        int
		FirstName string
		LastName  string
	}
	err = db.Query("SELECT * FROM people").Rows(&people)
	logFatal(err)
	for _, person := range people {
		log.Printf("Id: %v, First Name: %s, Last Name: %s",
			person.ID,
			person.FirstName,
			person.LastName)
	}
}

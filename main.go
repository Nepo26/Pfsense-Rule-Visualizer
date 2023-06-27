package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
)


func main() {

	// Open XML File
	xmlFile, err := os.Open("./config-firewall.xml")

	// if out os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Successfully Opened file")
	// defer the closing of our xmlFile so that we can parse it later on
    defer xmlFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(xmlFile)

	var pfsense Pfsense
	xml.Unmarshal(byteValue, &pfsense)


	fmt.Println(pfsense.System.Group)
	

}
package main

type ATT_ROLE int

const (
	IS_CA     ATT_ROLE = 0
	IS_LOGGER ATT_ROLE = 1
)

const (
	testAttPrivateKey = "PRIVATE+KEY+helloworld+b51acf1b+ASW28PXJDCV8klh7JeacIgfJR3/Q60dklasmgnv4c9I7"
	testAttPublicKey  = "helloworld+b51acf1b+AZ2ZM0ZQ69GwDUyO7/x0JyLo09y3geyufyN1mFFMeUH3"
)

type AttSession struct {
	round int
}

type AttClient struct {
	role ATT_ROLE
}

type AttMsg struct {
}

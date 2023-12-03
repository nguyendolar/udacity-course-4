import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'
// import { certificate } from '../../lambda/auth'

const logger = createLogger('auth')

const jwksUrl = 'https://test-endpoint.auth0.com/.well-known/jwks.json'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJbDa6183HFEBNMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi1tYnl1ZGJzNzdpMXhxZmtjLnVzLmF1dGgwLmNvbTAeFw0yMzEyMDMx
MzI1MDVaFw0zNzA4MTExMzI1MDVaMCwxKjAoBgNVBAMTIWRldi1tYnl1ZGJzNzdp
MXhxZmtjLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAJtl50FQwkxTfzX//57hsh7NM4pUbn40grvSdkSFqkZTB87Sluj1hypvy2pv
j1nHT7x6t5OQyPhKOLHn2jmb1mhDcHTXa9bK6ByI/pTj60mfzKREQJdE5pnmZqku
TQF/LFMA5yFuTrBCSbTf1jyYSSeUaOqCw2hJrNOezk5rTUuBQJwOydITJ+g7t+qb
bGAtmU4+ZeztJS3vTznMEcXcBA2CuK/mGesqozPrFqLllL9ylpFBJahSHIMn0OMM
FnIitMnW30cVxaW3zTlgYHJM59EHVJhPVwRAV/ISn5lZ8BfYuO8BUvAlw3NFrmIG
MKLaJ25tGW98vnlhAa3jdtN9ZusCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUvGQeulu2kGhhcdQV3O4JcFxrt20wDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQAS1/7XhV4wh2zrrp+gT7VJVI36pHLnAH0d5ItStSVi
rCP8gSxBj+5ZwR+6hwv5eqNnboMjDz521YQ4VEwgxDSqxJ/QR9OBp1gCCLUXjjqb
6opuBK1z8wp9bi7GEbVa1IwCT8HTAYnqgoACShb0qoMHcXzzTZ1wAehepZCVJA6J
v8TyOrQqslskL6lc9vjR605+X9LxlSbVtrq/KrG9GRi0jA7bn0S/HtSRHyyC6UUR
lJv7tV3SPPa2P7roZeDZsWRNeVaGWLL4LxUC8NGEHVPCcnKDlrZE6zvSrRtwvuGd
Mp3ZnYpPmKQyIs+1OFLXdM+xZfZZHm38ziJlIemws6jK
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  // TODO: Implement token verification
  jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
  return jwt;
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}

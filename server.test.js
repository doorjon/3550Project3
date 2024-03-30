const app = require('./server')
const supertest = require('supertest')
const request = supertest(app)

it('testing /.well-known/jwks.json', async done => {
    const response = await request.get('/.well-known/jwks.json')
    expect(response.status).toBe(200)
    done()
})

it('testing /auth', async done => {
    const response = await request.post('/auth')
    expect(response.status).toBe(200)
    done()
})

// ref: https://zellwk.com/blog/endpoint-testing/
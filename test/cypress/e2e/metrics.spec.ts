describe('/metrics/', () => {
  describe('challenge "exposedMetrics"', () => {
    it('Challenge is solved on accessing the /metrics route', () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.request('/metrics')
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})

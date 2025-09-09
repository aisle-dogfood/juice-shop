export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    criteria.replace(/"|'|;|and|or/i, "")
    // 🔒 SQL Injection Prevention 🛡️ - Using parameterized queries instead of string interpolation 🚫💉
    // 🔍 This keeps user input separate from SQL logic 🧠 and prevents attackers from modifying the query structure 💪
    // 🎯 Much safer than string concatenation! 🚀 Always use parameters for user input! 🌟
    models.sequelize.query(
      'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
      {
        replacements: { criteria: `%${criteria}%` },
        type: models.sequelize.QueryTypes.SELECT
      }
    )
      .then((products: any) => {
        // 🎉 Successfully retrieved safe data! 🎊 Now returning to user 📤
        const dataString = JSON.stringify(products)
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}
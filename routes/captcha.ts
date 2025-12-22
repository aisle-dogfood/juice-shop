/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { type Captcha } from '../data/types'
import { CaptchaModel } from '../models/captcha'

function safeCalculate (firstTerm: number, firstOperator: string, secondTerm: number, secondOperator: string, thirdTerm: number): number {
  // Calculate the expression following proper order of operations
  // First, handle multiplication operations
  let result: number
  let tempFirst = firstTerm
  let tempThird = thirdTerm
  
  if (firstOperator === '*') {
    tempFirst = firstTerm * secondTerm
    result = tempFirst
    if (secondOperator === '*') {
      result = tempFirst * thirdTerm
    } else if (secondOperator === '+') {
      result = tempFirst + thirdTerm
    } else { // '-'
      result = tempFirst - thirdTerm
    }
  } else if (secondOperator === '*') {
    tempThird = secondTerm * thirdTerm
    if (firstOperator === '+') {
      result = firstTerm + tempThird
    } else { // '-'
      result = firstTerm - tempThird
    }
  } else {
    // No multiplication, evaluate left to right
    if (firstOperator === '+') {
      tempFirst = firstTerm + secondTerm
    } else { // '-'
      tempFirst = firstTerm - secondTerm
    }
    
    if (secondOperator === '+') {
      result = tempFirst + thirdTerm
    } else { // '-'
      result = tempFirst - thirdTerm
    }
  }
  
  return result
}

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = safeCalculate(firstTerm, firstOperator, secondTerm, secondOperator, thirdTerm).toString()

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

export const verifyCaptcha = () => (req: Request, res: Response, next: NextFunction) => {
  CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } }).then((captcha: Captcha | null) => {
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  }).catch((error: Error) => {
    next(error)
  })
}

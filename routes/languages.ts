/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import locales from '../data/static/locales.json'
import { promises as fsPromises } from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

// Security limits to prevent resource exhaustion
const MAX_LANGUAGE_FILES = 100 // Maximum number of language files to process
const MAX_FILE_SIZE = 1024 * 1024 // Maximum file size: 1MB

export function getLanguageList () { // TODO Refactor and extend to also load backend translations from /i18n/*json and calculate joint percentage/gauge
  return async (req: Request, res: Response, next: NextFunction) => {
    const languages: Array<{ key: string, lang: any, icons: string[], shortKey: string, percentage: unknown, gauge: string }> = []
    const i18nDir = 'frontend/dist/frontend/assets/i18n/'

    try {
      // Read the English reference file
      const enFilePath = path.join(i18nDir, 'en.json')
      const enStats = await fsPromises.stat(enFilePath)
      
      // Validate English file size
      if (enStats.size > MAX_FILE_SIZE) {
        throw new Error(`English language file exceeds maximum size of ${MAX_FILE_SIZE} bytes`)
      }
      
      const enContent = JSON.parse(await fsPromises.readFile(enFilePath, 'utf-8'))

      // Read the directory
      let languageFiles = await fsPromises.readdir(i18nDir)
      
      // Filter to only .json files
      languageFiles = languageFiles.filter(file => file.endsWith('.json'))
      
      // Limit the number of files to process
      if (languageFiles.length > MAX_LANGUAGE_FILES) {
        languageFiles = languageFiles.slice(0, MAX_LANGUAGE_FILES)
      }

      // Process all language files
      for (const fileName of languageFiles) {
        const filePath = path.join(i18nDir, fileName)
        
        // Check file size before reading
        const stats = await fsPromises.stat(filePath)
        if (stats.size > MAX_FILE_SIZE) {
          // Skip files that are too large
          continue
        }
        
        const content = await fsPromises.readFile(filePath, 'utf-8')
        const fileContent = JSON.parse(content)
        const percentage = calcPercentage(fileContent, enContent)
        const key = fileName.substring(0, fileName.indexOf('.'))
        const locale = locales.find((l) => l.key === key)
        
        const lang: any = {
          key,
          lang: fileContent.LANGUAGE,
          icons: locale?.icons,
          shortKey: locale?.shortKey,
          percentage,
          gauge: (percentage > 90 ? 'full' : (percentage > 70 ? 'three-quarters' : (percentage > 50 ? 'half' : (percentage > 30 ? 'quarter' : 'empty'))))
        }
        
        if (!(fileName === 'en.json' || fileName === 'tlh_AA.json')) {
          languages.push(lang)
        }
      }

      languages.push({ key: 'en', icons: ['gb', 'us'], shortKey: 'EN', lang: 'English', percentage: 100, gauge: 'full' })
      languages.sort((a, b) => a.lang.localeCompare(b.lang))
      res.status(200).json(languages)
    } catch (err: any) {
      next(new Error(`Unable to retrieve language files: ${err.message}`))
    }

    function calcPercentage (fileContent: any, enContent: any): number {
      const totalStrings = Object.keys(enContent).length
      let differentStrings = 0
      
      for (const key in fileContent) {
        if (Object.prototype.hasOwnProperty.call(fileContent, key) && fileContent[key] !== enContent[key]) {
          differentStrings++
        }
      }
      
      return (differentStrings / totalStrings) * 100
    }
  }
}

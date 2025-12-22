/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import pug from 'pug'
import config from 'config'
import { type Request, type Response } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const entities = new Entities()

export const getVideo = () => {
  return (req: Request, res: Response) => {
    const path = videoPath()
    const stat = fs.statSync(path)
    const fileSize = stat.size
    const range = req.headers.range
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-')
      const start = parseInt(parts[0], 10)
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1
      const chunksize = (end - start) + 1
      const file = fs.createReadStream(path, { start, end })
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Location': '/assets/public/videos/owasp_promo.mp4',
        'Content-Type': 'video/mp4'
      }
      res.writeHead(206, head)
      file.pipe(res)
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': 'video/mp4'
      }
      res.writeHead(200, head)
      fs.createReadStream(path).pipe(res)
    }
  }
}

export const promotionVideo = () => {
  return (req: Request, res: Response) => {
    const templatePath = 'views/promotionVideo.pug'
    const maxTemplateSize = 1024 * 1024 // 1 MB limit for template file
    
    // Check template file size before reading
    try {
      const templateStat = fs.statSync(templatePath)
      if (templateStat.size > maxTemplateSize) {
        res.status(413).send('Template file too large')
        return
      }
    } catch (err) {
      res.status(500).send('Error accessing template file')
      return
    }

    fs.readFile(templatePath, function (err, buf) {
      if (err != null) {
        res.status(500).send('Error reading template file')
        return
      }
      
      try {
        let template = buf.toString()
        const subs = getSubsFromFile()

        challengeUtils.solveIf(challenges.videoXssChallenge, () => { return utils.contains(subs, '</script><script>alert(`xss`)</script>') })

        const themeKey = config.get<string>('application.theme') as keyof typeof themes
        const theme = themes[themeKey] || themes['bluegrey-lightgreen']
        template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
        template = template.replace(/_favicon_/g, favicon())
        template = template.replace(/_bgColor_/g, theme.bgColor)
        template = template.replace(/_textColor_/g, theme.textColor)
        template = template.replace(/_navColor_/g, theme.navColor)
        template = template.replace(/_primLight_/g, theme.primLight)
        template = template.replace(/_primDark_/g, theme.primDark)
        const fn = pug.compile(template)
        let compiledTemplate = fn()
        compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + subs + '</script>')
        res.send(compiledTemplate)
      } catch (error) {
        res.status(500).send('Error processing template')
      }
    })
  }
  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}

function getSubsFromFile () {
  const subtitles = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  const subtitlesPath = 'frontend/dist/frontend/assets/public/videos/' + subtitles
  const maxSubtitlesSize = 512 * 1024 // 512 KB limit for subtitle file
  
  // Check subtitle file size before reading
  try {
    const subtitlesStat = fs.statSync(subtitlesPath)
    if (subtitlesStat.size > maxSubtitlesSize) {
      throw new Error('Subtitle file too large')
    }
  } catch (err) {
    throw new Error('Error accessing subtitle file: ' + (err as Error).message)
  }
  
  const data = fs.readFileSync(subtitlesPath, 'utf8')
  return data.toString()
}

function videoPath () {
  if (config.get<string>('application.promotion.video') !== null) {
    const video = utils.extractFilename(config.get<string>('application.promotion.video'))
    return 'frontend/dist/frontend/assets/public/videos/' + video
  }
  return 'frontend/dist/frontend/assets/public/videos/owasp_promo.mp4'
}

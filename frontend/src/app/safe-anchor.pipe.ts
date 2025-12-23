/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Pipe, type PipeTransform } from '@angular/core'
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser'

/**
 * Pipe that adds rel="noopener noreferrer" to all anchor tags with target="_blank"
 * to prevent reverse tabnabbing attacks
 */
@Pipe({
  name: 'safeAnchor',
  standalone: true
})
export class SafeAnchorPipe implements PipeTransform {
  constructor (private readonly sanitizer: DomSanitizer) {}

  transform (html: string | SafeHtml): SafeHtml {
    if (!html) {
      return this.sanitizer.sanitize(1, '') || ''
    }

    // Convert SafeHtml to string if needed
    const htmlString = typeof html === 'string' ? html : html.toString()

    // Add rel="noopener noreferrer" to all target="_blank" anchors that don't already have it
    const transformedHtml = htmlString.replace(
      /<a\s+([^>]*?)target=["']_blank["']([^>]*?)>/gi,
      (match, before, after) => {
        // Check if rel attribute already exists
        const hasRel = /\srel\s*=/i.test(before + after)
        
        if (hasRel) {
          // If rel exists, check if it contains noopener and noreferrer
          const relMatch = (before + after).match(/\srel\s*=\s*["']([^"']*)["']/i)
          if (relMatch) {
            const relValue = relMatch[1]
            const hasNoopener = /\bnoopener\b/i.test(relValue)
            const hasNoreferrer = /\bnoreferrer\b/i.test(relValue)
            
            if (!hasNoopener || !hasNoreferrer) {
              // Add missing values to existing rel attribute
              let newRelValue = relValue
              if (!hasNoopener) {
                newRelValue += ' noopener'
              }
              if (!hasNoreferrer) {
                newRelValue += ' noreferrer'
              }
              return match.replace(/\srel\s*=\s*["'][^"']*["']/i, ` rel="${newRelValue.trim()}"`)
            }
          }
          return match
        } else {
          // Add rel="noopener noreferrer" if it doesn't exist
          return `<a ${before}target="_blank"${after} rel="noopener noreferrer">`
        }
      }
    )

    return this.sanitizer.bypassSecurityTrustHtml(transformedHtml)
  }
}

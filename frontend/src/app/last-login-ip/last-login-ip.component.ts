/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component } from '@angular/core'
import * as jwtDecode from 'jwt-decode'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

@Component({
  selector: 'app-last-login-ip',
  templateUrl: './last-login-ip.component.html',
  styleUrls: ['./last-login-ip.component.scss'],
  imports: [MatCardModule, TranslateModule]
})

export class LastLoginIpComponent {
  lastLoginIp: string = '?'
  constructor () {}

  ngOnInit (): void {
    try {
      this.parseAuthToken()
    } catch (err) {
      console.log(err)
    }
  }

  parseAuthToken () {
    let payload = {} as any
    const token = localStorage.getItem('token')
    if (token) {
      payload = jwtDecode(token)
      if (payload.data.lastLoginIp) {
        // Validate IP format before using - basic IPv4/IPv6 check
        const ipValue = String(payload.data.lastLoginIp)
        if (this.isValidIpFormat(ipValue)) {
          this.lastLoginIp = ipValue
        }
      }
    }
  }

  private isValidIpFormat (ip: string): boolean {
    // IPv4 format: xxx.xxx.xxx.xxx
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
    // IPv6 format: basic validation
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
    
    if (ipv4Regex.test(ip)) {
      // Validate each octet is 0-255
      const octets = ip.split('.')
      return octets.every(octet => {
        const num = parseInt(octet, 10)
        return num >= 0 && num <= 255
      })
    }
    
    return ipv6Regex.test(ip)
  }
}

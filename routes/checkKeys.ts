import { type Request, type Response } from 'express'
import { HDNodeWallet } from 'ethers'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import logger from '../lib/logger'

// Default mnemonic for demo/challenge purposes only
// In production, this should be set via ETH_MNEMONIC environment variable
const DEFAULT_MNEMONIC = 'purpose betray marriage blame crunch monitor spin slide donate sport lift clutch'

export function checkKeys () {
  return (req: Request, res: Response) => {
    try {
      // Load mnemonic from environment variable or use default for demo/challenge
      const mnemonic = process.env.ETH_MNEMONIC ?? DEFAULT_MNEMONIC
      
      // Log warning if using default mnemonic
      if (!process.env.ETH_MNEMONIC) {
        logger.warn('Using default mnemonic for NFT challenge. Set ETH_MNEMONIC environment variable for production use.')
      }
      
      const mnemonicWallet = HDNodeWallet.fromPhrase(mnemonic)
      const privateKey = mnemonicWallet.privateKey
      const publicKey = mnemonicWallet.publicKey
      const address = mnemonicWallet.address
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => {
        return req.body.privateKey === privateKey
      })
      if (req.body.privateKey === privateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (req.body.privateKey === address) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (req.body.privateKey === publicKey) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else {
          res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: challenges.nftUnlockChallenge })
        }
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
export function nftUnlocked () {
  return (req: Request, res: Response) => {
    try {
      res.status(200).json({ status: challenges.nftUnlockChallenge.solved })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}

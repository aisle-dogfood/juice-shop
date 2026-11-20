/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { type Request, type Response, type NextFunction } from "express";
import { type UserModel } from "models/user";
import expressJwt from "express-jwt";
import jwt from "jsonwebtoken";
import jws from "jws";
import sanitizeHtmlLib from "sanitize-html";
import sanitizeFilenameLib from "sanitize-filename";
import * as utils from "./utils";

interface JwtKeyPair {
  privateKey: string;
  publicKey: string;
}

const jwtPrivateKeyFile = path.resolve("encryptionkeys", "jwt.key");
const noFollow = (fs.constants as typeof fs.constants & { O_NOFOLLOW?: number }).O_NOFOLLOW;
const currentUserId = typeof process.getuid === "function" ? process.getuid() : undefined;

const requireNoFollowSupport = () => {
  if (noFollow === undefined) {
    throw new Error("JWT file fallback requires filesystem no-follow support");
  }
  return noFollow;
};

const derivePublicKey = (privateKey: string) =>
  crypto
    .createPublicKey(privateKey)
    .export({ type: "pkcs1", format: "pem" })
    .toString();

const assertSecurePath = (filePath: string, stats: fs.Stats, description: string) => {
  if (!stats.isFile() && !stats.isDirectory()) {
    throw new Error(`JWT ${description} must be a regular filesystem object`);
  }
  if (stats.isSymbolicLink() || (stats.mode & 0o077) !== 0) {
    throw new Error(`JWT ${description} has unsafe permissions or link type`);
  }
  if (currentUserId !== undefined && stats.uid !== currentUserId) {
    throw new Error(`JWT ${description} must be owned by the service user`);
  }
  if (filePath === jwtPrivateKeyFile && stats.size === 0) {
    throw new Error("JWT private key file must contain key material");
  }
};

const openedPath = (fileDescriptor: number) => {
  if (process.platform !== "linux") {
    throw new Error("JWT file fallback requires descriptor path verification");
  }
  return fs.realpathSync(`/proc/self/fd/${fileDescriptor}`);
};

const openKeyDirectory = () => {
  const directory = path.dirname(jwtPrivateKeyFile);
  const directoryFlag = (fs.constants as typeof fs.constants & { O_DIRECTORY?: number }).O_DIRECTORY;
  if (directoryFlag === undefined) {
    throw new Error("JWT file fallback requires directory descriptor support");
  }

  const directoryDescriptor = fs.openSync(directory, fs.constants.O_RDONLY | directoryFlag | requireNoFollowSupport());
  try {
    let stats = fs.fstatSync(directoryDescriptor);
    if (!stats.isDirectory() || (currentUserId !== undefined && stats.uid !== currentUserId)) {
      throw new Error("JWT private key directory must be owned and private");
    }
    if (currentUserId !== undefined && (stats.mode & 0o077) !== 0) {
      fs.fchmodSync(directoryDescriptor, 0o700);
      stats = fs.fstatSync(directoryDescriptor);
    }
    assertSecurePath(directory, stats, "private key directory");
    return { descriptor: directoryDescriptor, path: openedPath(directoryDescriptor) };
  } catch (error) {
    fs.closeSync(directoryDescriptor);
    throw error;
  }
};

const readPrivateKeyFile = (): string | undefined => {
  const directory = openKeyDirectory();
  let fileDescriptor: number | undefined;

  try {
    fileDescriptor = fs.openSync(jwtPrivateKeyFile, fs.constants.O_RDONLY | requireNoFollowSupport());
    if (openedPath(fileDescriptor) !== path.join(directory.path, "jwt.key")) {
      throw new Error("JWT private key path changed during initialization");
    }
  } catch (error: any) {
    if (fileDescriptor !== undefined) fs.closeSync(fileDescriptor);
    fs.closeSync(directory.descriptor);
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }

  if (fileDescriptor === undefined) throw new Error("JWT private key descriptor was not opened");
  const openedFileDescriptor = fileDescriptor;
  try {
    const stats = fs.fstatSync(openedFileDescriptor);
    assertSecurePath(jwtPrivateKeyFile, stats, "private key file");
    return fs.readFileSync(openedFileDescriptor, "utf8");
  } finally {
    fs.closeSync(openedFileDescriptor);
    fs.closeSync(directory.descriptor);
  }
};

const createPrivateKeyFile = (privateKey: string): boolean => {
  const directory = openKeyDirectory();
  const temporaryPath = path.join(directory.path, `.jwt.key.${process.pid}.${crypto.randomBytes(16).toString("hex")}.tmp`);
  let temporaryDescriptor: number | undefined;

  try {
    temporaryDescriptor = fs.openSync(
      temporaryPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | requireNoFollowSupport(),
      0o600,
    );
    if (openedPath(temporaryDescriptor) !== temporaryPath) {
      throw new Error("JWT private key temporary path changed during initialization");
    }
    fs.writeFileSync(temporaryDescriptor, privateKey, { encoding: "utf8" });
    fs.fsyncSync(temporaryDescriptor);
    assertSecurePath(temporaryPath, fs.fstatSync(temporaryDescriptor), "private key temporary file");
    fs.closeSync(temporaryDescriptor);
    temporaryDescriptor = undefined;

    fs.linkSync(temporaryPath, path.join(directory.path, "jwt.key"));
    return true;
  } catch (error: any) {
    if (error?.code === "EEXIST") return false;
    throw error;
  } finally {
    if (temporaryDescriptor !== undefined) fs.closeSync(temporaryDescriptor);
    try { fs.unlinkSync(temporaryPath) } catch { /* temporary file was published or never created */ }
    fs.closeSync(directory.descriptor);
  }
};

const generateJwtKeyPair = (): JwtKeyPair => {
  const keyPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });

  if (createPrivateKeyFile(keyPair.privateKey)) return keyPair;

  const storedPrivateKey = readPrivateKeyFile();
  if (!storedPrivateKey) throw new Error("JWT private key disappeared during initialization");
  return { privateKey: storedPrivateKey, publicKey: derivePublicKey(storedPrivateKey) };
};

const loadJwtKeyPair = (): JwtKeyPair => {
  const configuredPrivateKey = process.env.JWT_PRIVATE_KEY;
  if (configuredPrivateKey) {
    const derivedPublicKey = derivePublicKey(configuredPrivateKey);
    if (process.env.JWT_PUBLIC_KEY && process.env.JWT_PUBLIC_KEY !== derivedPublicKey) {
      throw new Error("JWT_PUBLIC_KEY does not match JWT_PRIVATE_KEY");
    }
    return { privateKey: configuredPrivateKey, publicKey: derivedPublicKey };
  }

  const storedPrivateKey = readPrivateKeyFile();
  if (storedPrivateKey) {
    const derivedPublicKey = derivePublicKey(storedPrivateKey);
    if (process.env.JWT_PUBLIC_KEY && process.env.JWT_PUBLIC_KEY !== derivedPublicKey) {
      throw new Error("JWT_PUBLIC_KEY does not match JWT_PRIVATE_KEY");
    }
    return { privateKey: storedPrivateKey, publicKey: derivedPublicKey };
  }

  return generateJwtKeyPair();
};

const { publicKey, privateKey } = loadJwtKeyPair();

export { publicKey };

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from "z85";

interface ResponseWithUser {
  status?: string;
  data: UserModel;
  iat?: number;
  exp?: number;
  bid?: number;
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>;
  idMap: Record<string, string>;
  put: (token: string, user: ResponseWithUser) => void;
  get: (token?: string) => ResponseWithUser | undefined;
  tokenOf: (user: UserModel) => string | undefined;
  from: (req: Request) => ResponseWithUser | undefined;
  updateFrom: (req: Request, user: ResponseWithUser) => any;
}

export const hash = (data: string) =>
  crypto.createHash("md5").update(data).digest("hex");
const hmac_key = "pa4qacea4VK9t9nGv7yZtwmj";
export const hmac = (data: string) =>
  crypto.createHmac("sha256", hmac_key).update(data).digest("hex");

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = "%00";
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte));
  }
  return str;
};

export const isAuthorized = () => expressJwt({ secret: publicKey } as any);
export const denyAll = () => expressJwt({ secret: "" + Math.random() } as any);
export const authorize = (user = {}) =>
  jwt.sign(user, privateKey, { expiresIn: "6h", algorithm: "RS256" });
export const verify = (token: string) =>
  token
    ? (jws.verify as (token: string, secret: string) => boolean)(
        token,
        publicKey,
      )
    : false;
export const decode = (token: string) => {
  return jws.decode(token)?.payload;
};

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html);
export const sanitizeLegacy = (input = "") =>
  input.replace(/<(?:\w+)\W+?[\w]/gi, "");
export const sanitizeFilename = (filename: string) =>
  sanitizeFilenameLib(filename);
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html);
  if (sanitized === html) {
    return html;
  } else {
    return sanitizeSecure(sanitized);
  }
};

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user;
    this.idMap[user.data.id] = token;
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined;
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined;
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req);
    return token ? this.get(token) : undefined;
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req);
    this.put(token, user);
  },
};

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers["x-user-email"] : undefined;
};

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + "-" + discount;
  return z85.encode(coupon);
};

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined;
  }
  const decoded = z85.decode(coupon);
  if (decoded && hasValidFormat(decoded.toString()) != null) {
    const parts = decoded.toString().split("-");
    const validity = parts[0];
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1];
      return parseInt(discount);
    }
  }
};

function hasValidFormat(coupon: string) {
  return coupon.match(
    /(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/,
  );
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  "https://github.com/juice-shop/juice-shop",
  "https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm", // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  "https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW", // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  "https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6", // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  "http://shop.spreadshirt.com/juiceshop",
  "http://shop.spreadshirt.de/juiceshop",
  "https://www.stickeryou.com/products/owasp-juice-shop/794",
  "http://leanpub.com/juice-shop",
]);

export const isRedirectAllowed = (url: string) => {
  let allowed = false;
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl); // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed;
};
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: "customer",
  deluxe: "deluxe",
  accounting: "accounting",
  admin: "admin",
};

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac("sha256", privateKey);
  return hmac.update(email + roles.deluxe).digest("hex");
};

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken =
      verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req));
    if (decodedToken?.data?.role === roles.accounting) {
      next();
    } else {
      res.status(403).json({ error: "Malicious activity detected" });
    }
  };
};

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req));
  return (
    decodedToken?.data?.role === roles.deluxe &&
    decodedToken?.data?.deluxeToken &&
    decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
  );
};

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req));
  return decodedToken?.data?.role === roles.customer;
};

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id;
      next();
    } catch (error: any) {
      res.status(401).json({ status: "error", message: error });
    }
  };
};

export const updateAuthenticatedUsers =
  () => (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.token || utils.jwtFrom(req);
    if (token) {
      jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
        if (err === null) {
          if (authenticatedUsers.get(token) === undefined) {
            authenticatedUsers.put(token, decoded);
            res.cookie("token", token);
          }
        }
      });
    }
    next();
  };

const { v4: uuidv4 } = require("uuid");
const bodyParser = require("body-parser");
const passport = require("passport");
const hcaptcha = require("hcaptcha");
const cors = require("cors");
const crypto = require("crypto");
const argon2 = require("argon2");

const responses = require("./responses.json");
let loginredirect,
  loggedinredirect,
  mfa_route,
  errorfn,
  database,
  usercollection,
  error_route,
  data,
  stripe,
  sms_verify_route,
  sms_route,
  codes,
  site_hcaptcha_secret,
  billing_currency,
  client,
  url,
  app;

const payment = {
  customer: "",
  region: "",
  transactions: [],
  balance: 0,
  trial_redeemed: false,
};

function encrypt(sdata, key, iv) {
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key), iv);
  let encrypted = cipher.update(sdata, "utf-8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

function hash(sdata) {
  const hash = crypto.createHash("sha256");
  hash.update(sdata, "utf8");
  return hash.digest("hex");
}

function decrypt(sdata, key, iv) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(key), iv);
  let decrypted = decipher.update(sdata, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}

async function argon2_hash(secret, password) {
  try {
    // Hash password
    const hash = await argon2.hash(password, { secret: Buffer.from(secret) });
    return hash;
  } catch (err) {
    console.error("Error hashing password:", err);
    return null;
  }
}

async function argon2_verify(secret, hash, password) {
  try {
    // Verify password
    const match = await argon2.verify(hash, password, {
      secret: Buffer.from(secret),
    });
    return match;
  } catch (err) {
    console.error("Error verifying password:", err);
    return false;
  }
}
setTimeout(() => {
  for (const key in responses) {
    let info = responses[key];
    if (info.redirect) {
      info.redirect = eval(
        info.redirect.startsWith("/") ? info.redirect.slice(1) : info.redirect
      );
      if (info.redirect === null || !info.redirect || info.redirect === "") {
        delete info.redirect;
      }
    }
  }
}, 500);

function respond(req, res, info) {
  if (req.body.responseType === "json") {
    res.json(info);
  } else if (info.redirect) {
    res.redirect(info.redirect);
  } else {
    errorfn(res, info.status, info.msg);
  }
}

const serializeAndDeserializeUser = (authMethod) => {
  passport.serializeUser((user, done) => done(null, user));

  passport.deserializeUser((user, done) => {
    if (user.authMethod === authMethod) {
      done(null, user.profile);
    } else {
      done(null, null);
    }
  });
};
const setupPassportStrategy = (strategyName, strategyConfig, authMethod) => {
  passport.use(
    new strategyName(
      strategyConfig,
      (accessToken, refreshToken, profile, done) => {
        const user = { profile, authMethod };
        return done(null, user);
      }
    )
  );
};

/**
 * Searches a mongodb collection
 *
 * @param {string} collection - The mongoDB collection object
 * @param {object} query - The object to query the db with

 */
async function searchdb(collection, query) {
  let result = await collection.find(query).toArray();
  return result;
}

/**
 * @typedef {Object} ExpressApp
 * @property {Express.Application} app - The Express application instance.
 */

async function initialise(config) {
  app = config.express_app;
  stripe = require("stripe")(config.stripe_secret);

  async function completed(session) {
    const sessionLI = await stripe.checkout.sessions.retrieve(session.id, {
      expand: ["line_items"],
    });
    if (sessionLI.line_items.data[0].quantity) {
      usercollection.updateOne(
        { email: session.customer_details.email },
        {
          $push: { "payment.transactions": session.id },
          $inc: { "payment.balance": sessionLI.line_items.data[0].quantity },
        }
      );
    }
  }

  app.post(
    "/webhooks/stripe",
    bodyParser.raw({ type: "application/json" }),
    (req, res) => {
      const sig = req.headers["stripe-signature"];

      let event;

      try {
        event = stripe.webhooks.constructEvent(
          req.body,
          sig,
          config.stripe_endpoint_secret
        );
      } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
      }

      switch (event.type) {
        case "checkout.session.completed": {
          const session = event.data.object;
          if (session.payment_status === "paid") {
            completed(session);
          }
          break;
        }

        case "checkout.session.async_payment_succeeded": {
          const session = event.data.object;
          completed(session);
          break;
        }

        case "checkout.session.async_payment_failed": {
          const session = event.data.object;
          usercollection.updateOne(
            { email: session.customer_details.email },
            { $push: { "payment.transactions": session.id } }
          );
          break;
        }
      }

      res.status(200).end();
    }
  );

  app.use(cors());
  app.use(require("cookie-parser")());
  app.use(bodyParser.json({ limit: "10mb" }));
  app.use(bodyParser.urlencoded({ extended: false, limit: "10mb" }));
  app.use(passport.initialize());
  app.use(passport.session());

  loginredirect = config.login_redirect;
  loggedinredirect = config.loggedin_redirect;
  error_route = config.error_redirect;
  data = config.userdata;
  site_hcaptcha_secret = config.hcaptcha_secret;
  errorfn = config.errorfunction;
  billing_currency = config.currency;
  url = config.app_url;

  const { MongoClient, ServerApiVersion } = require("mongodb");
  const client = new MongoClient(config.mongodb_connect_uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  });

  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    if (config.mongodb_connect_uri.startsWith("mongodb+srv://")) {
      console.log("Connected to external mongoDB deployment - mongoDB atlas");
    } else {
      console.log(
        "Connected to local mongoDB server: " + config.mongodb_connect_uri
      );
    }
  } catch (e) {
    console.error("Failed to connect to mongoDB");
    console.error(e);
  }

  database = client.db(config.db);
  usercollection = database.collection("users");
  codes = database.collection("codes");
  console.log("express-usercontrols w/mongoDB running!");
}

async function writeuser(req, res, user) {
  try {
    const userresults = await searchdb(usercollection, { email: user.email });
    if (userresults[0]) {
      if (userresults[0].access.ban_time > Date.now()) {
        errorfn(
          res,
          403,
          `You have been banned from this service until <t:${userresults[0].access.ban_time}>`
        );
        req.session.user = {};
        return;
      }

      if (
        !userresults[0].oauth.some((obj) => obj.method === user.oauth[0].method)
      ) {
        usercollection.updateOne(
          { email: user.email },
          {
            $push: {
              oauth: user.oauth[0],
              log: {
                action: "oauth_verify",
                timestamp: Date.now(),
                old: null,
                new: user.oauth[0],
              },
            },
          }
        );
        userresults[0].oauth.push(user.oauth[0]);
      }
      let { log, oauth, password, payment, ...uresponse } = userresults[0];

      req.session.user = uresponse;
      req.session.user = { email: user.email };
      res.redirect(loggedinredirect);
      return;
    } else {
      await usercollection.insertOne(user);
      let { log, oauth, password, payment, ...uresponse } = user;
      req.session.user = uresponse;
      res.redirect(loggedinredirect);
      req.session.user = { email: user.email };
      return;
    }
  } catch (e2) {
    errorfn(res, 500, "Server error: Could not log you in");
    console.error(e2);
  }
}

/**
 * Sets up a local email/password sign in
 * @param {Function} validate_email - The function that is called when an OTP (One Time Code) needs to be sent to a user via email - validate_email(email_address, OTP)
 * @param {string} default_mfa - The default multi-factor authentication method ("email" or null)
 * @param {string} auth_route - The route of your OTP (One Time Code) authentication page (if applicable) (for redirects, if json responses are being used, set to null)
 * @param {string} secret - The password hashing secret
 */
function local_auth(validate_email, default_mfa, auth_route, secret) {
  const emailregex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/;
  const passwordregex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;
  mfa_route = auth_route;
  app.get("/ping/session", async (req, res) => {
    req.session.euc_sessionping = req.session.euc_sessionping + 1 || 0;
    res.json(req.session.euc_sessionping);
  });

  app.post("/auth", validatecaptcha, async (req, res) => {
    if (
      emailregex.test(req.body.email) &&
      passwordregex.test(req.body.password)
    ) {
      let user = await searchdb(usercollection, {
        email: req.body.email,
      });
      if (user.length === 1) {
        await argon2_verify(secret, user[0].password, req.body.password).then(
          async (match) => {
            if (match) {
              if (user[0].mfa === "email") {
                req.session.euc = {
                  code: Math.random().toString().substring(2, 8),
                  mode: "mfa",
                  profile: user[0],
                };
                validate_email(
                  req.session.euc.code,
                  req.session.euc.profile.email
                );
                respond(req, res, responses.login_2fa);
              } else {
                req.session.user = user[0];
                respond(req, res, responses.success);
              }
            } else {
              respond(req, res, responses.incorrect_login);
              return;
            }
          }
        );
      } else {
        respond(req, res, responses.incorrect_login);
        return;
      }
    } else {
      respond(req, res, responses.incorrect_login);
    }
  });

  app.post("/auth/create", validatecaptcha, async (req, res) => {
    let user = await searchdb(usercollection, { email: req.body.email });
    if (user.length > 0) {
      respond(req, res, responses.account_exists);
    } else {
      if (
        emailregex.test(req.body.email) &&
        passwordregex.test(req.body.password)
      ) {
        req.session.euc = {
          code: Math.random().toString().substring(2, 8),
          mode: "create_account",
          profile: {
            email: req.body.email,
            password: req.body.password,
            firstname: req.body.firstname,
            lastname: req.body.lastname,
            language: req.body.language,
            country: req.body.country,
          },
        };

        await validate_email(
          req.session.euc.code, req.session.euc.profile.email
        );
        respond(req, res, responses.login_2fa);
      } else {
        respond(req, res, responses.invalid_login);

        return;
      }
    }
  });
  app.post("/auth/authenticate", validatecaptcha, async (req, res) => {
    if (!req.session.euc) {
      respond(req, res, responses.otp_error);
      req.session.destroy();
      return;
    }
    try {
      let mcodes = req.session.euc;
      if (!"attempts" in mcodes) {
        req.session.euc.attempts = 0;
      }
      if (mcodes.attempts > 3) {
        req.session.destroy();
        respond(req, res, responses.otp_limit);
        return;
      }
      if (mcodes.code === req.body.auth_code) {
        if (mcodes.mode === "create_account") {
          let mdata = mcodes.profile;
          let new_pwd = await argon2_hash(secret, mdata.password);
          let udata = {
            id: uuidv4(),
            email: mdata.email,
            emailstatus: true,
            phone: null,
            phone_update: 0,
            payment,
            image: ``,
            firstname: mdata.firstname,
            lastname: mdata.lastname,
            displayname: mdata.firstname,
            locale: `${mdata.language}-${mdata.country}`,
            timezone: "",
            oauth: [
              {
                id: mdata.email,
                method: "local",
              },
            ],
            mfa: default_mfa,
            password: new_pwd,
            access: { role: "user", ban_time: 0 },
            created: Date.now(),
            log: [
              {
                action: "email_verify",
                timestamp: Date.now(),
                old: null,
                new: mdata.email,
              },
            ],
            data: data,
          };

          await usercollection.insertOne(udata);
          req.session.user = udata;
          respond(req, res, responses.success);
        } else if (mcodes.mode === "change_email") {
          await usercollection.updateOne(
            { email: req.session.user.email },
            {
              $set: { email: mcodes.profile.new },
              $push: {
                log: {
                  action: "email_update",
                  timestamp: Date.now(),
                  old: mcodes.profile.old,
                  new: mcodes.profile.new,
                },
              },
            }
          );
          //req.session.destroy();
          respond(req, res, responses.changed_email);
        } else if (mcodes.mode === "change_password") {
          let u_info = mcodes.profile;
          let new_pwd = await argon2_hash(secret, u_info.new);

          await usercollection.updateOne(
            { email: u_info.email },
            {
              $set: { password: new_pwd },
              $push: {
                log: {
                  action: "password_update",
                  timestamp: Date.now(),
                  old: u_info.old,
                  new: new_pwd,
                },
              },
            }
          );
          respond(req, res, responses.changed_password);
        } else if (mcodes.mode === "mfa") {
          req.session.user = mcodes.profile;
          delete req.session.euc;
          respond(req, res, responses.success);
        } else {
          req.session.destroy();
          respond(req, res, responses.otp_error);
        }
      } else {
        req.session.euc.attempts = req.session.euc.attempts + 1;
        respond(req, res, responses.incorrect_otp);
        return;
      }
    } catch (e) {
      console.error(e);
      req.session.destroy();
      respond(req, res, responses.otp_error);
    }
  });

  app.post(
    "/auth/change/email",
    validatecaptcha,
    determineuser(false),
    async (req, res) => {
      let user = await searchdb(usercollection, {
        email: req.session.user.email,
      });

      if (user.length === 1) {
        await argon2_verify(secret, user[0].password, req.body.password).then(
          async (match) => {
            if (match) {
              req.session.euc = {
                mode: "change_email",
                code: Math.random().toString().substring(2, 8),
                profile: {
                  new: req.body.email,
                  old: req.session.user.email,
                },
              };
              await validate_email(
                req.session.euc.code,
                req.session.euc.profile.new
              );

              respond(req, res, responses.login_2fa);
            } else {
              respond(req, res, responses.incorrect_login);
              return;
            }
          }
        );
      } else {
        respond(req, res, responses.incorrect_login);
      }
    }
  );
  app.post("/auth/change/password", validatecaptcha, async (req, res) => {
    if (passwordregex.test(req.body.password)) {
      let reset_user = await searchdb(usercollection, {
        email: req.body.email,
      });
      if (reset_user.length > 0) {
        req.session.euc = {
          code: Math.random().toString().substring(2, 8),
          mode: "change_password",
          profile: {
            email: req.body.email,
            new: req.body.password,
            old: reset_user[0].password,
          },
        };
        await validate_email(
          req.session.euc.code,
          req.session.euc.profile.email
        );
      }
      respond(req, res, responses.authentication_pending);
    } else {
      respond(req, res, responses.invalid_login);
    }
  });
}

/**
 * validates hCaptcha completion 
 *
 * @param {object} req
 * @param {object} res

 */
validatecaptcha = async (req, res, next) => {
  try {
    let captcha = await hcaptcha.verify(
      site_hcaptcha_secret,
      req.body["h-captcha-response"]
    );
    if (captcha.success === true) {
      return next();
    } else {
      respond(req, res, responses.failed_captcha);
    }
  } catch {
    respond(req, res, responses.captcha_error);
  } //HERE 500 server ERROR
};

function validateuser(req, res, email_verified) {
  if (email_verified === false) {
    errorfn(
      res,
      405,
      `Authorisation failed. Selected sign in method has an unverified email.`
    );
    req.session.user = null;
    return false;
  }
}

/**
 * Sets up Discord OAuth2
 * @param {string} package_name - The other OAuth2 package (must be compatible with passportjs) to use.
 * @param {string} provider_name - The name of the provider as used in the oauth2 package.
 * @param {string} scope - The array of scopes to use in the oauth2.
 * @param {string} clientId - The client ID of the OAuth2 application.
 * @param {string} clientSecret - The client Secret of the OAuth2 application.
 * @param {object} db_format - The format of which the json from the oauth provider is in, to be converted to the format required by the database.
 */
function oauth2(
  package_name,
  provider_name,
  scope,
  clientId,
  clientSecret,
  db_format
) {
  const OtherStrategy = require(package_name).Strategy;

  passport.use(
    new OtherStrategy(
      {
        clientID: clientId,
        clientSecret: clientSecret,
        callbackURL: `${url}/auth/${provider_name}/callback`,
        scope,
        store: true,
      },
      (accessToken, refreshToken, profile, done) => {
        return done(null, profile);
      }
    )
  );

  serializeAndDeserializeUser(provider_name);

  app.get(
    `/auth/${provider_name}`,
    passport.authenticate(provider_name, { scope })
  );

  app.get(
    `/auth/${provider_name}/callback`,
    passport.authenticate(provider_name, { failureRedirect: error_route }),
    (req, res) => {
      const user = req.session.passport.user;

      let verified_email;
      if (db_format.email_verified === true) {
        verified_email = true;
      } else {
        verified_email = user[db_format.email_verified];
      }
      const userv = validateuser(req, res, verified_email);
      if (userv === false) {
        return;
      }

      writeuser(req, res, {
        id: uuidv4(),
        email: user[db_format.email],
        emailstatus: verified_email,
        phone: null,
        phone_update: 0,
        payment,
        image: user[db_format.image],
        firstname: user[db_format.lastname],
        lastname: user[db_format.firstname],
        displayname: user[db_format.displayname],
        locale: user[db_format.locale],
        timezone: "",
        oauth: [
          {
            id: user[db_format.userId],
            method: provider_name,
          },
        ],

        mfa: null,
        password: null,
        access: { role: "user", ban_time: 0 },
        created: Date.now(),
        log: [],
        data,
      });
    }
  );
}

/**
 * Sets up Discord OAuth2
 *
 * @param {string} clientId - The client ID of the OAuth2 application.
 * @param {string} clientSecret - The client Secret of the OAuth2 application.
 */
function discord_oauth2(clientId, clientSecret) {
  const DiscordStrategy = require("passport-discord").Strategy;

  passport.use(
    new DiscordStrategy(
      {
        clientID: clientId,
        clientSecret: clientSecret,
        callbackURL: url + "/auth/discord/callback",
        scope: ["identify", "email"],
        store: true,
      },
      (accessToken, refreshToken, profile, done) => {
        return done(null, profile);
      }
    )
  );

  serializeAndDeserializeUser("discord");

  app.get(
    "/auth/discord",
    passport.authenticate("discord", { scope: ["identify", "email"] })
  );

  app.get(
    "/auth/discord/callback",
    passport.authenticate("discord", { failureRedirect: error_route }),
    (req, res) => {
      const user = req.session.passport.user;
      const userv = validateuser(req, res, user.verified);
      if (userv === false) {
        return;
      }
      writeuser(req, res, {
        id: uuidv4(),
        email: user.email,
        emailstatus: user.verified,
        phone: null,
        phone_update: 0,
        payment,
        image: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
        firstname: null,
        lastname: null,
        displayname: user.global_name,
        locale: user.locale,
        timezone: "",
        oauth: [
          {
            id: user.id,
            method: "discord",
          },
        ],
        mfa: null,
        password: null,
        access: { role: "user", ban_time: 0 },
        created: Date.now(),
        log: [],
        data: data,
      });
    }
  );
}

/**
 * Sets up Google OAuth2
 *
 * @param {string} clientId - The client ID of the OAuth2 application.
 * @param {string} clientSecret - The client Secret of the OAuth2 application.
 */
function google_oauth2(clientId, clientSecret) {
  const GoogleStrategy = require("passport-google-oauth20").Strategy;

  setupPassportStrategy(
    GoogleStrategy,
    {
      clientID: clientId,
      clientSecret: clientSecret,
      callbackURL: `${url}/auth/google/callback`,
      store: true,
    },
    "google"
  );
  serializeAndDeserializeUser("google");

  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["openid email profile"] })
  );

  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: error_route }),
    (req, res) => {
      const user = req.session.passport.user.profile._json;
      const userv = validateuser(req, res, user.email_verified);
      if (userv === false) {
        return;
      }

      writeuser(req, res, {
        id: uuidv4(),
        email: user.email,
        emailstatus: user.email_verified,
        phone: null,
        phone_update: 0,
        payment,
        image: user.picture,
        firstname: user.given_name,
        lastname: user.family_name,
        displayname: user.given_name,
        locale: user.locale,
        timezone: "",
        oauth: [
          {
            id: user.sub,
            method: "google",
          },
        ],
        mfa: null,
        password: null,
        access: { role: "user", ban_time: 0 },
        created: Date.now(),
        log: [],
        data: data,
      });
    }
  );
}

/**
 * Sets up GitHub OAuth2
 *
 * @param {string} clientId - The client ID of the OAuth2 application.
 * @param {string} clientSecret - The client Secret of the OAuth2 application.
 */
function github_oauth2(clientId, clientSecret) {
  const GitHubStrategy = require("passport-github2").Strategy;

  setupPassportStrategy(
    GitHubStrategy,
    {
      clientID: clientId,
      clientSecret: clientSecret,
      callbackURL: `${url}/auth/github/callback`,
      scope: ["user:email"],
      store: true,
    },
    "github"
  );

  serializeAndDeserializeUser("github");

  app.get(
    "/auth/github",
    passport.authenticate("github", { scope: ["user:email"] })
  );

  app.get(
    "/auth/github/callback",
    passport.authenticate("github", { failureRedirect: error_route }),
    (req, res) => {
      const userv = validateuser(req, res, true);
      if (userv === false) {
        return;
      }
      const user = req.session.passport.user.profile._json;

      writeuser(req, res, {
        id: uuidv4(),
        email: req.session.passport.user.profile.emails[0].value,
        emailstatus: true,
        phone: null,
        phone_update: 0,
        payment,
        image: user.avatar_url,
        firstname: null,
        lastname: null,
        displayname: user.login,
        locale: null,
        timezone: "",
        oauth: [
          {
            id: user.id,
            method: "github",
          },
        ],
        mfa: null,
        password: null,
        access: { role: "user", ban_time: 0 },
        created: Date.now(),
        log: [],
        data: data,
      });
    }
  );
}

/**
 * Sets up Microsoft OAuth2
 *
 * @param {string} clientId - The client ID of the OAuth2 application.
 * @param {string} clientSecret - The client Secret of the OAuth2 application.
 */
function microsoft_oauth2(clientId, clientSecret) {
  const MicrosoftStrategy = require("passport-microsoft").Strategy;

  setupPassportStrategy(
    MicrosoftStrategy,
    {
      clientID: clientId,
      clientSecret: clientSecret,
      callbackURL: `${url}/auth/microsoft/callback`,
      scope: ["user.read"],
    },
    "microsoft"
  );

  serializeAndDeserializeUser("microsoft");

  app.get(
    "/auth/microsoft",
    passport.authenticate("microsoft", { scope: ["user.read"] })
  );

  app.get(
    "/auth/microsoft/callback",
    passport.authenticate("microsoft", { failureRedirect: error_route }),
    (req, res) => {
      const userv = validateuser(req, res, true);
      if (userv === false) {
        return;
      }

      const user = req.session.passport.user.profile._json;

      writeuser(req, res, {
        id: uuidv4(),
        email: user.mail,
        emailstatus: true,
        phone: null,
        phone_update: 0,
        payment,
        image: null,
        firstname: user.givenName,
        lastname: null,
        displayname: user.displayname,
        locale: user.preferredLanguage,
        timezone: "",
        oauth: [{ id: user.id, method: "microsoft" }],
        mfa: null,
        password: null,
        access: { role: "user", ban_time: 0 },
        created: Date.now(),
        log: [],
        data: data,
      });
    }
  );
}

/**
 * refreshes the user's info each time they load the selected route
 * @param {boolean} phone_verify - Whether a phone number needs to be attached to the user account to continue.
 */
determineuser = (phone_verify) => {
  return async (req, res, next) => {
    let user = req.session.user;
    if (user) {
      try {
        const userresults = await searchdb(usercollection, {
          email: user.email,
        });
        if (userresults[0].access.ban_time > Date.now()) {
          errorfn(
            res,
            403,
            `You have been banned from this service until <t:${userresults[0].access.ban_time}>`
          );
          return;
        }
        if (phone_verify === true) {
          if (userresults[0].phone === null || userresults[0].phone === "") {
            respond(req, res, responses.verify_phone);
            return;
          }
        }
        let { log, oauth, password, payment, ...uresponse } = userresults[0];
        req.session.user = uresponse;
        return next();
      } catch (e) {
        console.error(e);
        errorfn(res, 503, `Server error: Failed to connect to the database.`);
      }
    } else {
      res.redirect(loginredirect);
    }
  };
};

/**
 * Initiate one-time payment for the user.
 *
 * @param {string} req - The "req" attribute of the route
 * @param {string} res - The "res" attribute of the route
 * @param {string} product - The product to list for the payment
 * @param {string} quantity - The quantity of the product to charge for
 * @param {string} unit_amount - The unit amount of the product being charged
 * @param {string} successroute - The payment success route
 * @param {string} cancelroute - The payment cancellation route
 * @param {string} voucher - The v
 * 
 
 */

//stripe is disabled in v1.1.0
/*
async function stripe_bill(
  req,
  res,
  product,
  quantity,
  unit_amount,
  successroute,
  cancelroute,
  voucher
) {
  user_r = req.session.user;
  if (!user_r) {
    res.redirect(loginredirect);
  }
  let customer;
  if (user_r.payment.customer === "") {
    customer = await stripe.customers.create({
      email: user_r.email,
      phone: user_r.phone,
      name: user_r.name,
    });
    customer = customer.id;
    usercollection.updateOne(
      { email: user_r.email },
      { $set: { "payment.customer": customer } }
    );
  } else {
    customer = user_r.payment.customer;
  }

  let unitdiscounted;
  let total_price = unit_amount * quantity;
  if (voucher && voucher.code != null && voucher.code != "") {
    let searchcode, type;

    if (voucher.pin) {
      searchcode = { code: voucher.code, pin: voucher.pin };

      type = `gift card`;
    } else {
      searchcode = { code: voucher.code, pin: null };
      type = `promo code`;
    }
    let foundcodes = await searchdb(codes, searchcode);

    if (foundcodes.length < 1) {
      errorfn(res, 406, `Promo code entered doesn't exist`);
      return;
    }
    type = `${type} ${foundcodes[0].code} - ${foundcodes[0].discount.value}`;
    if (
      foundcodes[0].recipient != null &&
      foundcodes[0].recipient === user_r.email
    ) {
      errorfn(
        res,
        406,
        `The recipient of the discount code entered isn't you!`
      );
      return;
    }

    if (total_price < foundcodes[0].discount.min_purchase) {
      errorfn(
        res,
        406,
        `Your purchase does not meet the minimum purchase requirements for this discount code!`
      );
      return;
    }

    let discount_value = total_price * (foundcodes[0].discount.value / 100);

    if (
      foundcodes[0].discount.relative === true &&
      discount_value > foundcodes[0].discount.max_discount
    ) {
      errorfn(
        res,
        406,
        `The total discounted value of the entered code is too high for the code!`
      );
      return;
    }

    if (
      foundcodes[0].active === false ||
      (foundcodes[0].max_redemptions &&
        foundcodes[0].redemptions >= foundcodes[0].max_redemptions)
    ) {
      errorfn(res, 406`The selected discount is no longer active`);
      return;
    }

    if (foundcodes[0].discount.relative === true) {
      unitdiscounted = (total_price - discount_value) / quantity;
    } else {
      unitdiscounted = (total_price - foundcodes[0].discount.value) / quantity;
    }

    let activate = true;
    if (foundcodes[0].max_redemptions != null) {
      redeem = 1;
      if (!foundcodes[0].redemptions + 1 < foundcodes[0].max_redemptions) {
        activate = false;
      }
    }

    codes.updateOne(searchcode, {
      $inc: { redemptions: 1 },
      $set: { active: true },
    });
  } else {
    unitdiscounted = total_price;
  }

  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        quantity,
        price_data: {
          currency: billing_currency,
          product: product,
          unit_amount: unitdiscounted,
        },
      },
    ],
    mode: "payment",
    customer,
    success_url: url + successroute,
    cancel_url: url + cancelroute,
    determineuser,
  });
  res.redirect(303, session.url);
}
*/

/**
 * Sets up phone number verification for the user
 *
 * @param {string} authroute - The route of the phone number entry page
 * @param {string} authrouteverify - The route of the code entry page
 * @param {string} accountSid - credentials
 * @param {string} authToken - credentials
 * @param {string} verifySid - credentials
 * @param {integer} trial_balance - free trial amount that can be given to each new account upon phone verification
 */

function sms_verify(
  authroute,
  authrouteverify,
  accountSid,
  authToken,
  verifySid,
  trial_balance
) {
  sms_verify_route = authrouteverify;
  sms_route = authroute;
  const twverify = require("twilio")(accountSid, authToken);

  app.post(
    "/verify",
    validatecaptcha,
    determineuser(false),
    async (req, res) => {
      try {
        let user = req.session.user;

        if (!req.session.ph_count) {
          req.session.ph_count = 0;
        }

        if (req.session.ph_count >= 3) {
          respond(req, res, responses.phone_otp_limit);
          return;
        }

        if (Date.now() - user.phone_update < 518400000) {
          respond(req, res, responses.phone_update_limit);
          return;
        }

        await usercollection.updateOne(
          { email: user.email },
          {
            $push: {
              log: {
                action: "phone_send",
                timestamp: Date.now(),
                old: user.phone,
                new: verification_check.to,
              },
            },
          }
        );

        twverify.verify.v2
          .services(verifySid)
          .verifications.create({ to: req.body.phonenumber, channel: "sms" })
          .then((verification) => {
            req.session.euc.ph_auth = req.body.phonenumber;
            req.session.ph_count += 1;
            respond(req, res, responses.phone_authenticate);

            return;
          })
          .catch((error) => {
            respond(req, res, responses.phone_invalid);
            return;
          });
      } catch (e) {
        respond(req, res, responses.phone_error);
        return;
      }
    }
  );

  app.post(
    "/verify/callback",
    validatecaptcha,
    determineuser(false),
    async (req, res) => {
      let user = req.session.user;

      twverify.verify.v2
        .services(verifySid)
        .verificationChecks.create({
          to: req.session.euc.ph_auth,
          code: req.body.auth_code,
        })
        .then((verification_check) => {
          if (verification_check.status === "approved") {
            (async () => {
              await usercollection.updateOne(
                { email: user.email },
                {
                  $set: {
                    phone: verification_check.to,
                    phone_update: Date.now(),
                  },
                  $push: {
                    log: {
                      action: "phone_verify",
                      timestamp: Date.now(),
                      old: user.phone,
                      new: verification_check.to,
                    },
                  },
                }
              );

              let pb = await searchdb(usercollection, {
                "log.old": verification_check.to,
                "log.action": "phone_verify",
              });
              let psearch = await searchdb(usercollection, {
                phone: verification_check.to,
              });

              if (
                pb.length <= 0 &&
                psearch.length <= 0 &&
                user.payment.trial_redeemed === false
              ) {
                await usercollection.updateOne(
                  { email: user.email },
                  {
                    $inc: { "payment.balance": trial_balance },
                    $set: { "payment.trial_redeemed": true },
                  }
                );
              }

              req.session.euc.ph_auth = null;
              respond(req, res, responses.phone_update);
            })();
          } else {
            respond(req, res, responses.phone_code_invalid);
            return;
          }
        })
        .catch((error) => {
          respond(req, res, responses.phone_error);
          return;
        });
    }
  );

  app.post(
    "/verify/remove",
    validatecaptcha,
    determineuser(false),
    async (req, res) => {
      let user = req.session.user;

      await usercollection.updateOne(
        { email: user.email },
        {
          $push: {
            log: {
              action: "phone_remove",
              timestamp: Date.now(),
              old: user.phone,
              new: "",
            },
          },
        }
      );

      usercollection.updateOne(
        { email: user.email },
        {
          $set: { phone: null, phone_update: Date.now() },
        }
      );

      respond(req, res, responses.phone_remove);
    }
  );
}

module.exports = {
  discord_oauth2,
  google_oauth2,
  github_oauth2,
  microsoft_oauth2,
  initialise,
  determineuser,
  //stripe_bill,
  sms_verify,
  searchdb,
  validatecaptcha,
  local_auth,
};

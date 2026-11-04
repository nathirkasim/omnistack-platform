// Production bundled JavaScript asset

// GT: id=EVASION-SEC-015 type=TP rule=jwt-secret-in-code technique=plain pair_id=EVASION-SEC-016
const PLAIN_JWT_SIGNING_KEY = process.env.JWT_SIGNING_KEY || "";

// GT: id=EVASION-SEC-016 type=TP rule=jwt-secret-in-code technique=minified-js-comment pair_id=EVASION-SEC-015
var _0x1a=function(){/* jwt_secret dynamically loaded from process.env.JWT_SECRET */};

// PhishCatcher Finding Explanation Library

const findingExplanations = {
  dkim_fail: {
    meaning: "DKIM uses a digital signature to help verify that an email was authorized by its sending domain and that signed portions of the message have not been altered.",

    whyItMatters: "A failed verification means the signature could not be verified. This may happen because of an invalid signature, email configuration issues, or message modifications. It does not automatically mean the email is malicious."
  }, 
  spf_fail: {
  meaning: "SPF checks whether the server sending an email is authorized by the sender's domain.",

  whyItMatters: "The sending server did not pass the domain's SPF check. This can indicate an unauthorized sending source or an issue with the domain's email configuration."
},

spf_mixed: {
  meaning: "SPF checks whether the server sending an email is authorized by the sender's domain.",

  whyItMatters: "Multiple SPF results were found, and some passed while others failed. This means the authentication results were inconsistent."
},

dkim_mixed: {
  meaning: "An email can contain multiple DKIM signatures, which are used to verify its authenticity and signed content.",

  whyItMatters: "Some signatures passed verification while others failed. This means the email had inconsistent DKIM authentication results."
},

dmarc_fail: {
  meaning: "DMARC checks whether an email's sender domain aligns with its SPF or DKIM authentication results and applies the domain's email policy.",

  whyItMatters: "The email did not meet the domain's DMARC requirements. This may indicate a sender authentication or domain alignment issue."
},

dmarc_mixed: {
  meaning: "DMARC checks whether an email's sender domain aligns with its SPF or DKIM authentication results and applies the domain's email policy.",

  whyItMatters: "Multiple DMARC results were found, and they differed. This means the authentication results were inconsistent."
}
};
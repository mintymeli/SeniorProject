const toolInfo = {
  virustotal: {
    title: "About VirusTotal",

    sections: [
      {
        heading: "What is VirusTotal?",
        paragraphs: [
          "VirusTotal is an online service that helps identify potentially harmful websites, IP addresses, files, and other digital content.",
          "It gathers results from many different security companies and their tools so users can see what those tools have found in one place."
        ],
        definitions: [
          {
            term: "Vendor",
            meaning: "A security company or service that provides tools to identify potential threats."
          },
          {
            term: "Report",
            meaning: "A record containing the results of security checks performed on an indicator, such as a domain or IP address."
          },
          {
            term: "Detection",
            meaning: "When a security tool identifies or flags something as potentially harmful or suspicious."
          }
        ]
      },

      {
        heading: "How does PhishCatcher use it?",
        paragraphs: [
          "When you analyze an email, PhishCatcher extracts domains and public IP addresses from its email headers.",
          "It then checks VirusTotal for existing reports on those indicators to see whether security tools have previously identified potentially harmful or suspicious activity.",
          "This provides additional information about the websites and servers involved in delivering an email, helping users recognize indicators that may deserve further investigation."
        ]
      },

      {
        heading: "How do I read the results?",
        paragraphs: [
          "VirusTotal displays how many security tools assigned each classification to the domain or IP address being checked."
        ],
        definitions: [
          {
            term: "Malicious",
            meaning: "The number of security tools that identified the indicator as associated with harmful activity."
          },
          {
            term: "Suspicious",
            meaning: "The number of security tools that flagged the indicator as potentially concerning, but did not classify it as malicious."
          },
          {
            term: "Harmless",
            meaning: "The number of security tools that classified the indicator as harmless. This does not guarantee that it is completely safe."
          },
          {
            term: "Undetected",
            meaning: "The number of security tools that did not identify a threat. This does not necessarily mean the indicator is safe."
          }
        ],        
        paragraphsAfterDefinitions: [
        "A vendor fraction shows how many vendors gave a particular classification compared with the total number of vendors included in the analysis.",
        ],
      }, 

      {
          heading: "What is the Final URL?",
          paragraphs: [
            "The final url is the destination you reach after clicking the original url. Sometimes, it may pass through several different web pages before reaching its final destination.",
            "PhishCatcher uses VirusTotal to help identify where the original URL may eventually lead. This gives a better idea of its potential destination before visiting the site.",
            "In the example below, the Original URL is the link displayed in the email. When clicked, it may redirect to another website. The Final URL shows where the link eventually leads."
      ],
      redirectExample: {
        original: "example.com/redirect",
        destination: "example.com/download/file"
      },
      },

      {
        heading: "Let's look at an example",

        example: {
          description: "Imagine PhishCatcher returns these results for a domain:",
          total: 92,
          results: [
            { label: "Malicious", count: 5 },
            { label: "Suspicious", count: 3 },
            { label: "Harmless", count: 60 },
            { label: "Undetected", count: 20 }
          ],
          steps: [
            "Start with the total: 92 vendors are included in this analysis.",
            "Look at Malicious: 5 vendors identified the domain as associated with harmful activity.",
            "Look at Suspicious: 3 vendors flagged the domain as potentially concerning.",
            "Look at Harmless: 60 vendors classified the domain as harmless.",
            "Look at Undetected: 20 vendors did not identify a threat.",
            "Consider all the results together. The 5 malicious detections are worth investigating, even though many other vendors did not flag the domain."
          ],
          note: "This example uses a domain, but the same explanation applies to IP address and URL results. The values may differ depending on the indicator being analyzed."
        }
      },

      {
        heading: "Things to keep in mind",
        paragraphs: [
          "Different security vendors may reach different conclusions about the same indicator.",
          "Reports may be incomplete or outdated, so the results may not reflect the indicator's current activity.",
          "A URL's final destination may not always be available or accurately identified.",
          "Zero detections does not guarantee that a domain or IP address is safe.",
          "A detection is a reason to investigate further, not proof by itself that an email is malicious."
        ]
      }
    ],

    disclosure: {
      heading: "Disclosure",
      text: "The total number of vendors includes all vendors whose results are part of the analysis, including those that did not provide a malicious, suspicious, harmless, or undetected classification. Because of this, the four category counts may not add up to the total."
    }
  },
  
  // IPQS info
  ipqs: {
      title: "About IPQualityScore",
      sections: [
          {
              heading: "What is IPQualityScore?",
              paragraphs: [
                  "IPQualityScore (IPQS) is a service that checks links for signs of potentially unsafe or suspicious activity.",
                  "It looks for warning signs that a website may be connected to scams, phishing, or malware."
              ]
          },
          {
              heading: "How does PhishCatcher use it?",
              paragraphs: [
                  "When you analyze an email, PhishCatcher sends the links found in the message to IPQualityScore for analysis.",
                  "IPQS checks each link and returns information that can help you understand whether it may be risky."
              ]
          },
          {
              heading: "How do I read the results?",
              paragraphs: [
                  "IPQualityScore provides several results to help you understand the link:"
              ],
              definitions: [
                  {
                      term: "Safe",
                      meaning: "Indicates whether IPQS considers the link safe based on its analysis. A safe result does not guarantee that the website is harmless."
                  },
                  {
                      term: "Suspicious",
                      meaning: "Indicates whether IPQS found signs that the link may be connected to suspicious activity."
                  },
                  {
                      term: "Domain",
                      meaning: "The website name associated with the link's destination."
                  },
                  {
                      term: "Malware",
                      meaning: "Indicates whether the link is associated with harmful software that could affect a device."
                  },
                  {
                      term: "Phishing",
                      meaning: "Indicates whether the link may lead to a website designed to trick people into sharing personal information, such as passwords."
                  },
                  {
                      term: "Risk Score",
                      meaning: "A score from 0 to 100 that estimates how risky a link may be. A higher score means IPQS sees more signs of risk. Scores of 85 or higher are considered high risk by IPQS."
                  },
                  {
                      term: "Domain Age",
                      meaning: "How long the website's domain has been registered. A newly registered domain may deserve extra attention, but its age alone does not mean it is unsafe."
                  }
              ],
              paragraphsAfterDefinitions: [
                  "Look at these results together rather than relying on just one of them."
              ]
          },
          {
              heading: "Let's look at an example",
              example: {
                  description: "Imagine an email contains a link to example.com. IPQualityScore analyzes the link and returns these results:",
                  total: 0,
                  results: [
                      { label: "Safe", count: "Yes" },
                      { label: "Suspicious", count: "No" },
                      { label: "Domain", count: "example.com" },
                      { label: "Malware", count: "No" },
                      { label: "Phishing", count: "No" },
                      { label: "Risk Score", count: 12 },
                      { label: "Domain Age", count: "18 years ago" }
                  ],
                  steps: [
                    "Start with Safe: the result is Yes, meaning IPQS did not classify the link as unsafe.",
                    "Look at Suspicious: the result is No, meaning IPQS did not flag the link as suspicious.",
                    "Check Malware and Phishing: both results are No, meaning IPQS did not identify signs of malware or phishing.",
                    "Look at Risk Score: the score is 12, which is below IPQS's high-risk threshold of 85.",
                    "Check Domain Age: the domain has been registered for 18 years. This gives us additional context about the website, but does not prove that it is safe.",
                    "Consider all the results together. IPQS did not flag this link in these checks, but that does not guarantee it is harmless."
                ],
                  note: "This is an example to help explain the results. Actual results may differ depending on the link being analyzed."
              }
          },
          {
              heading: "Things to keep in mind",
              paragraphs: [
                  "IPQualityScore provides warning signs, not a guarantee that a website is safe or harmful.",
                  "A low risk score does not guarantee that a link is safe. A high score means the link deserves closer attention.",
                  "A website's age is only one clue. Both new and older websites can be used for harmful activity."
              ]
          }
      ]
  },

  // AbuseIPDB info
  abuseipdb: {
    title: "About AbuseIPDB",
  
    sections: [
      {
        heading: "What is AbuseIPDB?",
        paragraphs: [
          "AbuseIPDB is an online service that collects and shares reports about IP addresses associated with abusive activity, such as spam, hacking attempts, and other suspicious behavior.",
          "It allows users and security professionals to check whether an IP address has previously been reported for potentially harmful activity."
        ]
      },
      {
        heading: "How does PhishCatcher use it?",
        paragraphs: [
          "When you analyze an email, PhishCatcher extracts IP addresses from its email headers.",
          "It filters out non-public IP addresses and checks the remaining public IP addresses against AbuseIPDB's existing records.",
          "PhishCatcher retrieves information such as the Abuse Confidence Score, Total Reports, country, ISP, and whitelist status. It looks up existing information; it does not submit abuse reports."
        ]
      },
      {
        heading: "How do I read the results?",
        paragraphs: [
          "Each result provides information about the IP address and its history in AbuseIPDB."
        ],
        definitions: [
          {
            term: "Abuse Confidence Score",
            meaning: "A score from 0 to 100 based on reports submitted about an IP address. A higher score indicates greater concern about reported abusive activity, not the probability that the IP address is malicious."
          },
          {
            term: "Total Reports",
            meaning: "The number of abuse reports submitted about this IP address and recorded by AbuseIPDB."
          },
          {
            term: "Country",
            meaning: "The country associated with the IP address. This does not necessarily tell us where the person who sent the email is located."
          },
          {
            term: "ISP (Internet Service Provider)",
            meaning: "The organization that provides or manages the internet connection associated with the IP address. For example, this could be an internet provider, university, or hosting company."
          },
          {
            term: "Whitelisted",
            meaning: "Indicates whether AbuseIPDB has marked the IP address as trusted. Yes means it is on the whitelist, while No means it is not. A whitelisted IP address is not automatically guaranteed to be safe."
          }
        ]
      },
      {
        heading: "Let's look at an example",
        example: {
          description: "Imagine PhishCatcher returns the following results for the IP address 192.0.2.10:",
          total: 0,
          results: [
            { label: "Abuse Confidence Score", count: 75 },
            { label: "Total Reports", count: 12 },
            { label: "Country", count: "US" },
            { label: "ISP", count: "Example University" },
            { label: "Whitelisted", count: "No" }
          ],
          steps: [
            "Start with the Abuse Confidence Score: A score of 75 indicates considerable concern about reported abusive activity associated with this IP address.",
            "Look at Total Reports: The IP address has 12 abuse reports recorded by AbuseIPDB.",
            "Check the Country: The IP address is associated with the United States.",
            "Look at the ISP: Example University is listed as the organization associated with the IP address.",
            "Check Whitelisted: The result is No, meaning AbuseIPDB has not marked this IP address as trusted.",
            "Consider all the results together: The score and report history suggest the IP address deserves further investigation, but they do not prove that the email is malicious."
          ]
        }
      },
      {
        heading: "Things to keep in mind",
        paragraphs: [
          "AbuseIPDB relies on reports submitted by users. Reports may vary in accuracy and can become outdated.",
          "An IP address may be shared by multiple websites, services, organizations, or users. A report does not necessarily mean the current owner or sender is responsible for the activity.",
          "A score of zero or no reports does not guarantee that an IP address is safe.",
          "AbuseIPDB results are one source of threat intelligence and should be considered alongside the other findings in PhishCatcher."
        ]
      }
    ]
  },
  
  // URLHaus info
  
urlhaus: {
    title: "About URLhaus",
    sections: [
        {
            heading: "What is URLhaus?",
            paragraphs: [
                "URLhaus is a threat intelligence service that collects and shares links reported for distributing malware (harmful software).",
                "It helps identify links that may lead to websites used to deliver harmful files or infect devices."
            ],
            definitions: [
                {
                    term: "Spamhaus Domain Blocklist (DBL)",
                    meaning: "A list maintained by Spamhaus that identifies domains associated with spam, phishing, malware, and other abusive activity."
                },
                {
                    term: "Spam URI Realtime Blocklists (SURBL)",
                    meaning: "Lists that identify website addresses and domains associated with spam, phishing, malware, and other harmful activity."
                }
            ]
        },
        {
            heading: "How does PhishCatcher use it?",
            paragraphs: [
                "When you analyze an email, PhishCatcher checks the links found in the message against URLhaus.",
                "If a link has been reported, URLhaus can provide details such as its reported threat type, whether it is still online, and whether it appears on certain blocklists."
            ]
        },
        {
            heading: "How do I read the results?",
            paragraphs: [
                "URLhaus provides several details to help you understand a reported link:"
            ],
            definitions: [
                {
                    term: "URL Status",
                    meaning: "Indicates whether the reported link is still accessible. Online means the link can currently be reached; Offline means it could not be reached when checked. Online does not mean the link is safe."
                },
                {
                    term: "Host",
                    meaning: "The website or server hosting the reported link."
                },
                {
                    term: "Date Added",
                    meaning: "When the link was added to URLhaus's database."
                },
                {
                    term: "Threat Type",
                    meaning: "Describes the type of harmful activity associated with the link. For example, malware_download means the link was reported for distributing harmful software that could infect a device."
                },
                {
                    term: "URLhaus Blocklist",
                    meaning: "Indicates whether the URL appears on URLhaus's list of reported harmful links. Blocked means it was found on the list; Not blocked means it was not found."
                },
                {
                    term: "Spamhaus DBL",
                    meaning: "Indicates whether the domain appears on Spamhaus's Domain Blocklist. Blocked means it was found on the list; Not blocked means it was not found."
                },
                {
                    term: "SURBL",
                    meaning: "Indicates whether the domain appears on a SURBL list. Blocked means it was found on the list; Not blocked means it was not found."
                }
            ],
            paragraphsAfterDefinitions: [
                "Each blocklist checks for different types of suspicious activity. A domain not appearing on one list does not guarantee that it is safe. Consider all the results together when evaluating a link."
            ]
        },
        {
            heading: "Let's look at an example",
            example: {
                description: "Imagine an email contains a link that URLhaus has previously reported. Here is an example of the information it returns:",
                total: 0,
                results: [
                    { label: "URL Status", count: "Online" },
                    { label: "Host", count: "example.com" },
                    { label: "Date Added", count: "2026-11-15 10:30:00 UTC" },
                    { label: "Threat Type", count: "malware_download" },
                    { label: "URLhaus Blocklist", count: "Blocked" },
                    { label: "Spamhaus DBL", count: "Not blocked" },
                    { label: "SURBL", count: "Not blocked" }
                ],
                steps: [
                  "Start with URL Status: the link is Online, which means it can still be accessed. Remember, that does not mean it's safe to open.",
                  "Look at Threat Type: malware_download means the link was reported for distributing harmful software.",
                  "Check URLhaus Blocklist: the result is Blocked, meaning URLhaus has this link on its list of reported harmful links.",
                  "Look at Spamhaus DBL and SURBL: neither list identified this domain. However, that does not cancel out the URLhaus warning.",
                  "Consider all the results together. URLhaus has reported this link for distributing harmful software, so it should be treated with caution."
                ],
                note: "This is an illustrative example. Actual results may differ depending on the link being analyzed."
            }
        },
        {
            heading: "Things to keep in mind",
            paragraphs: [
                "URLhaus focuses on links reported for distributing malware. It does not check for every type of online threat.",
                "A link that is not found in URLhaus may still be harmful. It may simply not have been reported or added to the database.",
                "Online only describes whether a link is accessible. It does not mean the website is trustworthy.",
                "Blocklist results provide additional information, but Not blocked does not guarantee that a link is safe."
            ]
        }
    ]
  }
};
import { useState } from "react"
import axios from "axios"

const API_URL = "http://127.0.0.1:5000"

// ── Reusable panel wrapper ─────────────────────────────────────────────────
const Panel = ({ title, children }) => (
  <div className="panel p-5 rounded">
    <h2 className="text-sm tracking-widest opacity-50 mb-4">▶ {title}</h2>
    {children}
  </div>
)

// ── Key/value row ──────────────────────────────────────────────────────────
const Row = ({ label, value }) => (
  <div className="flex justify-between text-sm mb-2 border-b border-[#00ff4111] pb-1">
    <span className="opacity-50 shrink-0 mr-4">{label}</span>
    <span className="text-right break-all">{value ?? "—"}</span>
  </div>
)

// ── Verdict badge ──────────────────────────────────────────────────────────
const Verdict = ({ v }) => {
  const colors = {
    CLEAN:     "text-green-400 border-green-400",
    SUSPICIOUS:"text-yellow-400 border-yellow-400",
    MALICIOUS: "text-red-500 border-red-500",
    UNKNOWN:   "text-gray-400 border-gray-400"
  }
  return (
    <span className={`text-xs font-bold px-2 py-1 rounded border ${colors[v] || colors.UNKNOWN}`}>
      {v || "UNKNOWN"}
    </span>
  )
}

// ── Tab button ─────────────────────────────────────────────────────────────
const Tab = ({ label, active, onClick }) => (
  <button
    onClick={onClick}
    className={`px-4 py-2 text-xs tracking-widest transition-all duration-200 border-b-2 ${
      active
        ? "border-[#00ff41] text-[#00ff41]"
        : "border-transparent opacity-40 hover:opacity-70"
    }`}
  >
    {label}
  </button>
)

// ══════════════════════════════════════════════════════════════════════════════
export default function App() {

  // ── Shared state ──────────────────────────────────────────────────────────
  const [activeTab, setActiveTab]       = useState("domain")
  const [loading, setLoading]           = useState(false)
  const [error, setError]               = useState(null)
  const [history, setHistory]           = useState([])
  const [showHistory, setShowHistory]   = useState(false)

  // ── Per-tab inputs ─────────────────────────────────────────────────────────
  const [domain,   setDomain]     = useState("")
  const [ipTarget, setIpTarget]   = useState("")
  const [username, setUsername]   = useState("")
  const [phone,    setPhone]      = useState("")
  const [fileUrl,  setFileUrl]    = useState("")

  // ── Per-tab results ────────────────────────────────────────────────────────
  const [domainResults,    setDomainResults]    = useState(null)
  const [subdomainResults, setSubdomainResults] = useState(null)
  const [threatResults,    setThreatResults]    = useState(null)
  const [socialResults,    setSocialResults]    = useState(null)
  const [phoneResults,     setPhoneResults]     = useState(null)
  const [companyResults,   setCompanyResults]   = useState(null)
  const [fileResults,      setFileResults]      = useState(null)
  const [metaResults,      setMetaResults]      = useState(null)

  const reset = () => { setError(null) }

  // ── SCAN HANDLERS ──────────────────────────────────────────────────────────

  const handleDomainScan = async () => {
    if (!domain) return
    setLoading(true); reset()
    setDomainResults(null); setSubdomainResults(null)
    setThreatResults(null); setCompanyResults(null); setFileResults(null)
    try {
      const [scanRes, subRes, threatRes, compRes, fileRes] = await Promise.all([
        axios.post(`${API_URL}/api/scan`,       { domain }),
        axios.post(`${API_URL}/api/subdomains`, { domain }),
        axios.post(`${API_URL}/api/threat`,     { target: domain, type: "domain" }),
        axios.post(`${API_URL}/api/company`,    { domain }),
        axios.post(`${API_URL}/api/files`,      { domain }),
      ])
      setDomainResults(scanRes.data)
      setSubdomainResults(subRes.data)
      setThreatResults(threatRes.data)
      setCompanyResults(compRes.data)
      setFileResults(fileRes.data)
    } catch { setError("Domain scan failed. Is the backend running?") }
    finally { setLoading(false) }
  }

  const handleIpScan = async () => {
    if (!ipTarget) return
    setLoading(true); reset(); setThreatResults(null)
    try {
      const res = await axios.post(`${API_URL}/api/threat`, { target: ipTarget, type: "ip" })
      setThreatResults(res.data)
    } catch { setError("IP scan failed.") }
    finally { setLoading(false) }
  }

  const handleSocialScan = async () => {
    if (!username) return
    setLoading(true); reset(); setSocialResults(null)
    try {
      const res = await axios.post(`${API_URL}/api/social`, { username })
      setSocialResults(res.data)
    } catch { setError("Social scan failed.") }
    finally { setLoading(false) }
  }

  const handlePhoneScan = async () => {
    if (!phone) return
    setLoading(true); reset(); setPhoneResults(null)
    try {
      const res = await axios.post(`${API_URL}/api/phone`, { phone })
      setPhoneResults(res.data)
    } catch { setError("Phone lookup failed.") }
    finally { setLoading(false) }
  }

  const handleMetaScan = async () => {
    if (!fileUrl) return
    setLoading(true); reset(); setMetaResults(null)
    try {
      const res = await axios.post(`${API_URL}/api/files/metadata`, { url: fileUrl })
      setMetaResults(res.data)
    } catch (err) {
      // Surface the *real* reason instead of a generic message:
      // - err.response.data.error  -> backend returned JSON with an error (4xx/5xx we control)
      // - err.response.status      -> backend returned something we didn't expect (e.g. 404 = route doesn't exist)
      // - err.message              -> request never reached the backend at all (server down, wrong port, CORS)
      const backendMsg = err.response?.data?.error
      const detail = backendMsg
        ? backendMsg
        : err.response
          ? `Server responded with ${err.response.status}. Is /api/files/metadata registered and is the backend running the latest code?`
          : `${err.message}. Is the backend running on ${API_URL}?`
      setError(`Metadata extraction failed: ${detail}`)
    }
    finally { setLoading(false) }
  }

  const loadHistory = async () => {
    try {
      const res = await axios.get(`${API_URL}/api/history`)
      setHistory(res.data.scans)
      setShowHistory(true)
    } catch { console.error("Failed to load history") }
  }

  // ── LOADING STEPS per tab ─────────────────────────────────────────────────
  const loadingSteps = {
    domain: ["Fetching WHOIS data...","Enumerating DNS records...","Scanning open ports...",
             "Analyzing HTTP headers...","Detecting technologies...","Geolocating IP...",
             "Discovering subdomains...","Running threat intelligence...","Scanning exposed files...","Calculating risk score..."],
    ip:       ["Querying VirusTotal...","Checking AbuseIPDB...","Scanning AlienVault OTX...","Fetching URLScan results..."],
    social:   ["Checking GitHub...","Checking Twitter/X...","Checking Instagram...","Searching 16 platforms..."],
    phone:    ["Validating number format...","Querying carrier data...","Checking country info..."],
    file:     ["Downloading file...","Parsing document structure...","Extracting metadata fields..."],
  }

  const currentSteps = loadingSteps[activeTab] || loadingSteps.domain

  // ══════════════════════════════════════════════════════════════════════════
  return (
    <div className="min-h-screen bg-[#0d0d0d] text-[#00ff41] font-mono p-6">

      {/* HEADER */}
      <div className="text-center mb-8">
        <h1 className="text-5xl font-bold neon-text tracking-widest">🔍 DEEPFINDER</h1>
        <p className="text-sm mt-2 opacity-50 tracking-widest">
          EXTERNAL ATTACK SURFACE MANAGEMENT — OSINT PLATFORM v2.0
        </p>
        <div className="w-full h-px bg-[#00ff41] opacity-20 mt-4" />
      </div>

      {/* TABS */}
      <div className="max-w-4xl mx-auto mb-6 flex gap-0 border-b border-[#00ff4122] overflow-x-auto">
        <Tab label="🌐 DOMAIN"   active={activeTab==="domain"}   onClick={() => setActiveTab("domain")} />
        <Tab label="🖥️ IP"        active={activeTab==="ip"}       onClick={() => setActiveTab("ip")} />
        <Tab label="👤 USERNAME" active={activeTab==="social"}   onClick={() => setActiveTab("social")} />
        <Tab label="📞 PHONE"    active={activeTab==="phone"}    onClick={() => setActiveTab("phone")} />
        <Tab label="📄 FILE META" active={activeTab==="file"}    onClick={() => setActiveTab("file")} />
      </div>

      {/* SEARCH BAR — changes based on tab */}
      <div className="max-w-4xl mx-auto mb-6">
        <div className="flex gap-3 neon-border p-3 rounded">
          <span className="opacity-50 text-lg">$</span>

          {activeTab === "domain" && (
            <input type="text" placeholder="Enter domain (e.g. example.com)"
              value={domain} onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key==="Enter" && handleDomainScan()}
              className="flex-1 bg-transparent outline-none text-[#00ff41] placeholder-[#00ff41] placeholder-opacity-30 text-lg" />
          )}
          {activeTab === "ip" && (
            <input type="text" placeholder="Enter IP address (e.g. 8.8.8.8)"
              value={ipTarget} onChange={e => setIpTarget(e.target.value)}
              onKeyDown={e => e.key==="Enter" && handleIpScan()}
              className="flex-1 bg-transparent outline-none text-[#00ff41] placeholder-[#00ff41] placeholder-opacity-30 text-lg" />
          )}
          {activeTab === "social" && (
            <input type="text" placeholder="Enter username (e.g. johndoe)"
              value={username} onChange={e => setUsername(e.target.value)}
              onKeyDown={e => e.key==="Enter" && handleSocialScan()}
              className="flex-1 bg-transparent outline-none text-[#00ff41] placeholder-[#00ff41] placeholder-opacity-30 text-lg" />
          )}
          {activeTab === "phone" && (
            <input type="text" placeholder="Enter phone number (e.g. +12125551234)"
              value={phone} onChange={e => setPhone(e.target.value)}
              onKeyDown={e => e.key==="Enter" && handlePhoneScan()}
              className="flex-1 bg-transparent outline-none text-[#00ff41] placeholder-[#00ff41] placeholder-opacity-30 text-lg" />
          )}
          {activeTab === "file" && (
            <input type="text" placeholder="Enter public file URL (e.g. https://example.com/doc.pdf)"
              value={fileUrl} onChange={e => setFileUrl(e.target.value)}
              onKeyDown={e => e.key==="Enter" && handleMetaScan()}
              className="flex-1 bg-transparent outline-none text-[#00ff41] placeholder-[#00ff41] placeholder-opacity-30 text-lg" />
          )}

          <button onClick={() => {
            if (activeTab==="domain") handleDomainScan()
            else if (activeTab==="ip") handleIpScan()
            else if (activeTab==="social") handleSocialScan()
            else if (activeTab==="phone") handlePhoneScan()
            else if (activeTab==="file") handleMetaScan()
          }} disabled={loading}
            className="px-6 py-2 border border-[#00ff41] hover:bg-[#00ff41] hover:text-black transition-all duration-300 font-bold tracking-widest disabled:opacity-30">
            {loading ? "SCANNING..." : "SCAN"}
          </button>
        </div>
        <p className="text-xs opacity-30 mt-2 ml-6">
          ⚠ Only scan targets you own or have explicit written permission to test
        </p>
      </div>

      {/* HISTORY BUTTON */}
      <div className="max-w-4xl mx-auto mb-6 text-right">
        <button onClick={loadHistory}
          className="text-sm opacity-50 hover:opacity-100 border border-[#00ff4133] hover:border-[#00ff41] px-4 py-2 transition-all duration-300 tracking-widest">
          📋 SCAN HISTORY
        </button>
      </div>

      {/* LOADING */}
      {loading && (
        <div className="max-w-4xl mx-auto panel p-6 rounded mb-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-3 h-3 rounded-full bg-[#00ff41] animate-ping" />
            <span className="text-lg tracking-widest">SCANNING TARGET...</span>
          </div>
          {currentSteps.map((step, i) => (
            <div key={i} className="text-sm opacity-50 ml-6 mb-1">→ {step}</div>
          ))}
        </div>
      )}

      {/* ERROR */}
      {error && (
        <div className="max-w-4xl mx-auto p-4 border border-red-500 text-red-400 rounded mb-6">
          ❌ {error}
        </div>
      )}


      {/* ══════════════════════════════════════════════════════════════════════
          DOMAIN TAB RESULTS
      ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === "domain" && domainResults && (
        <div className="max-w-6xl mx-auto space-y-6">

          {/* Risk Score */}
          <div className="panel p-6 rounded text-center">
            <p className="text-sm opacity-50 tracking-widest mb-2">RISK SCORE</p>
            <div className={`text-7xl font-bold mb-2 ${
              domainResults.risk.level==="LOW"      ? "text-green-400" :
              domainResults.risk.level==="MEDIUM"   ? "text-yellow-400" :
              domainResults.risk.level==="HIGH"     ? "text-orange-400" : "text-red-500"
            }`}>{domainResults.risk.score}</div>
            <div className={`text-2xl font-bold tracking-widest ${
              domainResults.risk.level==="LOW"      ? "text-green-400" :
              domainResults.risk.level==="MEDIUM"   ? "text-yellow-400" :
              domainResults.risk.level==="HIGH"     ? "text-orange-400" : "text-red-500"
            }`}>{domainResults.risk.level}</div>
            <p className="text-sm opacity-40 mt-2">{domainResults.risk.total_issues} issues detected</p>
          </div>

          {/* Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

            {/* WHOIS */}
            <Panel title="WHOIS INFORMATION">
              {Object.entries(domainResults.whois).map(([k,v]) => (
                <Row key={k} label={k} value={v} />
              ))}
            </Panel>

            {/* DNS */}
            <Panel title="DNS RECORDS">
              {Object.entries(domainResults.dns).map(([type, records]) => (
                <div key={type} className="mb-3">
                  <span className="text-xs opacity-50">{type}</span>
                  {records.length > 0 ? records.map((r,i) => (
                    <div key={i} className="text-sm ml-4 text-[#00ff41]">→ {r}</div>
                  )) : <div className="text-sm ml-4 opacity-30">No records</div>}
                </div>
              ))}
            </Panel>

            {/* PORTS */}
            <Panel title="OPEN PORTS">
              {domainResults.ports.open_ports?.length > 0 ? (
                domainResults.ports.open_ports.map((p,i) => (
                  <div key={i} className="flex justify-between text-sm mb-2 border-b border-[#00ff4111] pb-1">
                    <span className="text-yellow-400 font-bold">{p.port}</span>
                    <span className="opacity-70">{p.service}</span>
                    <span className="text-green-400 text-xs">OPEN</span>
                  </div>
                ))
              ) : <p className="opacity-30 text-sm">No open ports found</p>}
            </Panel>

            {/* GEOLOCATION */}
            <Panel title="GEOLOCATION">
              {Object.entries(domainResults.geolocation).map(([k,v]) => (
                <Row key={k} label={k} value={v} />
              ))}
            </Panel>

            {/* HEADERS */}
            <Panel title="SECURITY HEADERS">
              <div className="mb-3">
                <p className="text-xs text-green-400 mb-2">✔ PRESENT ({domainResults.headers.present_count})</p>
                {Object.keys(domainResults.headers.security_headers_present || {}).length > 0
                  ? Object.keys(domainResults.headers.security_headers_present).map(h => (
                      <div key={h} className="text-sm text-green-400 mb-1 ml-2">✔ {h}</div>
                    ))
                  : <p className="text-sm opacity-30 ml-2">None</p>}
              </div>
              <div>
                <p className="text-xs text-red-400 mb-2">✘ MISSING ({domainResults.headers.missing_count})</p>
                {Object.keys(domainResults.headers.security_headers_missing || {}).map(h => (
                  <div key={h} className="text-sm text-red-400 mb-1 ml-2">✘ {h}</div>
                ))}
              </div>
            </Panel>

            {/* TECHNOLOGIES */}
            <Panel title="TECHNOLOGIES">
              {Object.entries(domainResults.technologies.technologies || {}).length > 0
                ? Object.entries(domainResults.technologies.technologies).map(([cat, techs]) => (
                    <div key={cat} className="mb-3">
                      <span className="text-xs opacity-50 uppercase">{cat}</span>
                      {techs.map((t,i) => <div key={i} className="text-sm ml-4">→ {t}</div>)}
                    </div>
                  ))
                : <p className="opacity-30 text-sm">No technologies detected</p>}
            </Panel>

          </div>

          {/* SUBDOMAINS */}
          {subdomainResults && (
            <Panel title={`SUBDOMAINS (${subdomainResults.total_found} found via ${subdomainResults.sources?.join(", ")})`}>
              {subdomainResults.total_found === 0
                ? <p className="opacity-30 text-sm">No subdomains discovered</p>
                : <div className="grid grid-cols-1 md:grid-cols-2 gap-1 max-h-64 overflow-y-auto">
                    {subdomainResults.subdomains.map((sub, i) => (
                      <div key={i} className="text-sm text-[#00ff41] border-b border-[#00ff4111] pb-1">
                        → {sub}
                      </div>
                    ))}
                  </div>}
            </Panel>
          )}

          {/* THREAT INTEL */}
          {threatResults && (
            <Panel title="THREAT INTELLIGENCE">
              <div className="flex items-center gap-4 mb-4">
                <span className="text-sm opacity-50">Overall Verdict</span>
                <Verdict v={threatResults.overall_verdict} />
                {threatResults.ip && <span className="text-xs opacity-40">IP: {threatResults.ip}</span>}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* VirusTotal */}
                <div className="border border-[#00ff4122] p-3 rounded">
                  <p className="text-xs opacity-50 mb-2 tracking-widest">VIRUSTOTAL</p>
                  {threatResults.virustotal?.error
                    ? <p className="text-xs text-red-400">{threatResults.virustotal.error}</p>
                    : <>
                        <Row label="Malicious"  value={threatResults.virustotal?.malicious} />
                        <Row label="Suspicious" value={threatResults.virustotal?.suspicious} />
                        <Row label="Clean"      value={threatResults.virustotal?.clean} />
                        <Row label="Reputation" value={threatResults.virustotal?.reputation_score} />
                        <div className="mt-2"><Verdict v={threatResults.virustotal?.verdict} /></div>
                      </>}
                </div>
                {/* AbuseIPDB */}
                <div className="border border-[#00ff4122] p-3 rounded">
                  <p className="text-xs opacity-50 mb-2 tracking-widest">ABUSEIPDB</p>
                  {threatResults.abuseipdb?.error
                    ? <p className="text-xs text-red-400">{threatResults.abuseipdb.error}</p>
                    : <>
                        <Row label="Abuse Score"   value={`${threatResults.abuseipdb?.abuse_score}%`} />
                        <Row label="Total Reports" value={threatResults.abuseipdb?.total_reports} />
                        <Row label="ISP"           value={threatResults.abuseipdb?.isp} />
                        <Row label="TOR Exit"      value={threatResults.abuseipdb?.is_tor ? "YES ⚠" : "No"} />
                        <div className="mt-2"><Verdict v={threatResults.abuseipdb?.verdict} /></div>
                      </>}
                </div>
                {/* OTX */}
                <div className="border border-[#00ff4122] p-3 rounded">
                  <p className="text-xs opacity-50 mb-2 tracking-widest">ALIENVAULT OTX</p>
                  {threatResults.otx?.error
                    ? <p className="text-xs text-red-400">{threatResults.otx.error}</p>
                    : <>
                        <Row label="Threat Pulses" value={threatResults.otx?.pulse_count} />
                        <Row label="In Threat Feed" value={threatResults.otx?.in_threat_feeds ? "YES ⚠" : "No"} />
                        {threatResults.otx?.threat_tags?.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {threatResults.otx.threat_tags.map((tag,i) => (
                              <span key={i} className="text-xs border border-red-500 text-red-400 px-1 rounded">{tag}</span>
                            ))}
                          </div>
                        )}
                        <div className="mt-2"><Verdict v={threatResults.otx?.verdict} /></div>
                      </>}
                </div>
              </div>
              {/* URLScan */}
              {threatResults.urlscan?.recent_scans?.length > 0 && (
                <div className="mt-4">
                  <p className="text-xs opacity-50 mb-2 tracking-widest">URLSCAN.IO — RECENT SCANS ({threatResults.urlscan.total_scans} total)</p>
                  {threatResults.urlscan.recent_scans.slice(0,3).map((scan, i) => (
                    <div key={i} className="flex justify-between text-xs mb-1 border-b border-[#00ff4111] pb-1">
                      <span className="opacity-50">{scan.date?.slice(0,10)}</span>
                      <span className="truncate max-w-xs">{scan.url}</span>
                      <span className={scan.malicious ? "text-red-400" : "text-green-400"}>
                        {scan.malicious ? "⚠ MALICIOUS" : "✔ CLEAN"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          )}

          {/* COMPANY */}
          {companyResults && (
            <Panel title="COMPANY INFORMATION">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  {companyResults.logo_url && (
                    <img src={companyResults.logo_url} alt="logo"
                      className="w-12 h-12 mb-3 rounded opacity-80"
                      onError={e => e.target.style.display="none"} />
                  )}
                  <Row label="Name"        value={companyResults.company_name} />
                  <Row label="Industry"    value={companyResults.industry} />
                  <Row label="Employees"   value={companyResults.employee_count} />
                  <Row label="Country"     value={companyResults.country} />
                  <Row label="City"        value={companyResults.city} />
                  <Row label="Email Pattern" value={companyResults.email_pattern} />
                  {companyResults.description && (
                    <p className="text-xs opacity-50 mt-2">{companyResults.description}</p>
                  )}
                </div>
                <div>
                  {Object.keys(companyResults.social_links || {}).length > 0 && (
                    <>
                      <p className="text-xs opacity-50 mb-2 tracking-widest">SOCIAL LINKS</p>
                      {Object.entries(companyResults.social_links).map(([k,v]) => (
                        <Row key={k} label={k} value={v} />
                      ))}
                    </>
                  )}
                  {companyResults.emails_found?.length > 0 && (
                    <>
                      <p className="text-xs opacity-50 mt-4 mb-2 tracking-widest">EMAILS FOUND ({companyResults.emails_found.length})</p>
                      {companyResults.emails_found.map((e,i) => (
                        <div key={i} className="text-xs border-b border-[#00ff4111] pb-1 mb-1">
                          <span className="text-[#00ff41]">{e.value}</span>
                          <span className="opacity-40 ml-2">{e.position || e.type}</span>
                          <span className="opacity-40 ml-2">{e.confidence ? `${e.confidence}% conf.` : ""}</span>
                        </div>
                      ))}
                    </>
                  )}
                </div>
              </div>
            </Panel>
          )}

          {/* EXPOSED FILES */}
          {fileResults && (
            <Panel title={`EXPOSED FILES & PATHS (${fileResults.exposed_count} found / ${fileResults.paths_checked} checked)`}>
              {fileResults.exposed_count === 0
                ? <p className="opacity-30 text-sm">No exposed paths detected</p>
                : fileResults.exposed_paths.map((p, i) => (
                    <div key={i} className={`text-sm mb-2 p-2 rounded border ${
                      p.risk?.startsWith("CRITICAL") ? "border-red-500 text-red-400" :
                      p.risk?.startsWith("HIGH")     ? "border-orange-500 text-orange-400" :
                      p.risk?.startsWith("MEDIUM")   ? "border-yellow-500 text-yellow-400" :
                      "border-[#00ff4133] text-[#00ff41]"
                    }`}>
                      <div className="flex justify-between">
                        <span className="font-bold">{p.path}</span>
                        <span className="text-xs opacity-70">HTTP {p.status}</span>
                      </div>
                      <div className="text-xs opacity-60 mt-1">{p.risk}</div>
                    </div>
                  ))
              }
              <div className="mt-4">
                <p className="text-xs opacity-50 mb-2 tracking-widest">GOOGLE DORKS (copy & search manually)</p>
                <div className="max-h-40 overflow-y-auto">
                  {fileResults.google_dorks?.map((dork, i) => (
                    <div key={i} className="text-xs font-mono bg-[#00ff4108] border border-[#00ff4122] p-1 mb-1 rounded break-all select-all">
                      {dork}
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          )}

          {/* RISK DETAILS */}
          <Panel title="RISK DETAILS">
            {domainResults.risk.details.map((d, i) => (
              <div key={i} className={`flex justify-between text-sm mb-2 p-2 rounded border ${
                d.severity==="high"   ? "border-red-500 text-red-400" :
                d.severity==="medium" ? "border-yellow-500 text-yellow-400" :
                "border-green-500 text-green-400"
              }`}>
                <span>[{d.category}] {d.issue}</span>
                <span className="font-bold">+{d.points} pts</span>
              </div>
            ))}
          </Panel>

        </div>
      )}


      {/* ══════════════════════════════════════════════════════════════════════
          IP TAB RESULTS
      ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === "ip" && threatResults && (
        <div className="max-w-6xl mx-auto space-y-6">
          <Panel title={`THREAT INTELLIGENCE — ${threatResults.target}`}>
            <div className="flex items-center gap-4 mb-6">
              <span className="text-sm opacity-50">Overall Verdict</span>
              <Verdict v={threatResults.overall_verdict} />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="border border-[#00ff4122] p-3 rounded">
                <p className="text-xs opacity-50 mb-2 tracking-widest">VIRUSTOTAL</p>
                {threatResults.virustotal?.error
                  ? <p className="text-xs text-red-400">{threatResults.virustotal.error}</p>
                  : <>
                      <Row label="Malicious"  value={threatResults.virustotal?.malicious} />
                      <Row label="Suspicious" value={threatResults.virustotal?.suspicious} />
                      <Row label="Clean"      value={threatResults.virustotal?.clean} />
                      <div className="mt-2"><Verdict v={threatResults.virustotal?.verdict} /></div>
                    </>}
              </div>
              <div className="border border-[#00ff4122] p-3 rounded">
                <p className="text-xs opacity-50 mb-2 tracking-widest">ABUSEIPDB</p>
                {threatResults.abuseipdb?.error
                  ? <p className="text-xs text-red-400">{threatResults.abuseipdb.error}</p>
                  : <>
                      <Row label="Abuse Score"   value={`${threatResults.abuseipdb?.abuse_score}%`} />
                      <Row label="Total Reports" value={threatResults.abuseipdb?.total_reports} />
                      <Row label="Country"       value={threatResults.abuseipdb?.country} />
                      <Row label="ISP"           value={threatResults.abuseipdb?.isp} />
                      <Row label="TOR Exit"      value={threatResults.abuseipdb?.is_tor ? "YES ⚠" : "No"} />
                      <Row label="Last Reported" value={threatResults.abuseipdb?.last_reported?.slice(0,10)} />
                      <div className="mt-2"><Verdict v={threatResults.abuseipdb?.verdict} /></div>
                    </>}
              </div>
              <div className="border border-[#00ff4122] p-3 rounded">
                <p className="text-xs opacity-50 mb-2 tracking-widest">ALIENVAULT OTX</p>
                {threatResults.otx?.error
                  ? <p className="text-xs text-red-400">{threatResults.otx.error}</p>
                  : <>
                      <Row label="Threat Pulses"  value={threatResults.otx?.pulse_count} />
                      <Row label="In Threat Feed" value={threatResults.otx?.in_threat_feeds ? "YES ⚠" : "No"} />
                      <div className="mt-2"><Verdict v={threatResults.otx?.verdict} /></div>
                    </>}
              </div>
            </div>
          </Panel>
        </div>
      )}


      {/* ══════════════════════════════════════════════════════════════════════
          SOCIAL TAB RESULTS
      ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === "social" && socialResults && (
        <div className="max-w-6xl mx-auto space-y-6">
          <Panel title={`SOCIAL MEDIA FOOTPRINT — @${socialResults.username} (${socialResults.total_found} profiles found)`}>
            {socialResults.found.length > 0 && (
              <>
                <p className="text-xs text-green-400 mb-3 tracking-widest">✔ FOUND ({socialResults.found.length})</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-6">
                  {socialResults.found.map((r, i) => (
                    <div key={i} className="flex justify-between items-center text-sm p-2 border border-green-500 rounded">
                      <span className="font-bold text-green-400">{r.platform}</span>
                      <a href={r.url} target="_blank" rel="noopener noreferrer"
                        className="text-xs opacity-50 hover:opacity-100 underline truncate max-w-xs ml-2">
                        {r.url}
                      </a>
                    </div>
                  ))}
                </div>
              </>
            )}
            {socialResults.blocked.length > 0 && (
              <>
                <p className="text-xs text-yellow-400 mb-2 tracking-widest">⚠ BLOCKED / MAY EXIST ({socialResults.blocked.length})</p>
                <div className="flex flex-wrap gap-2 mb-4">
                  {socialResults.blocked.map((r,i) => (
                    <span key={i} className="text-xs border border-yellow-500 text-yellow-400 px-2 py-1 rounded">{r.platform}</span>
                  ))}
                </div>
              </>
            )}
            {socialResults.not_found.length > 0 && (
              <>
                <p className="text-xs opacity-30 mb-2 tracking-widest">✘ NOT FOUND ({socialResults.not_found.length})</p>
                <div className="flex flex-wrap gap-2">
                  {socialResults.not_found.map((r,i) => (
                    <span key={i} className="text-xs opacity-30 border border-[#00ff4122] px-2 py-1 rounded">{r.platform}</span>
                  ))}
                </div>
              </>
            )}
          </Panel>
        </div>
      )}


      {/* ══════════════════════════════════════════════════════════════════════
          PHONE TAB RESULTS
      ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === "phone" && phoneResults && (
        <div className="max-w-6xl mx-auto space-y-6">
          <Panel title="PHONE NUMBER LOOKUP">
            {phoneResults.error && phoneResults.valid === null ? (
              <p className="text-red-400 text-sm">{phoneResults.error}</p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Row label="Input"   value={phoneResults.input} />
                <Row label="Cleaned" value={phoneResults.cleaned} />
              </div>
            )}
          </Panel>

          {!phoneResults.error && (
            <>
              <Panel title="INFORMATION">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
                  <Row label="Line Type" value={phoneResults.line_type} />
                  <Row label="Carrier"   value={phoneResults.carrier} />
                  <Row label="MCC"       value={phoneResults.mcc} />
                  <Row label="MNC"       value={phoneResults.mnc} />
                </div>
              </Panel>

              <Panel title="FORMAT">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
                  <Row label="International" value={phoneResults.international_format} />
                  <Row label="National"      value={phoneResults.local_format} />
                </div>
              </Panel>

              <Panel title="LOCATION">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
                  <Row label="Country"        value={phoneResults.country} />
                  <Row label="Country Code"   value={phoneResults.country_code} />
                  <Row label="Country Prefix" value={phoneResults.country_prefix} />
                  <Row label="Region"         value={phoneResults.region} />
                  <Row label="City"           value={phoneResults.city} />
                  <Row label="Timezone"       value={phoneResults.timezone} />
                </div>
              </Panel>

              <Panel title="MESSAGING">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
                  <Row label="SMS Domain" value={phoneResults.sms_domain} />
                  <Row label="SMS Email"  value={phoneResults.sms_email} />
                </div>
              </Panel>

              <Panel title="VALIDATION">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
                  <Row label="Valid"        value={phoneResults.valid ? "✔ YES" : "✘ NO"} />
                  <Row label="Line Status"  value={phoneResults.line_status} />
                  <Row label="VoIP"         value={phoneResults.is_voip === null ? "—" : (phoneResults.is_voip ? "✔ YES" : "✘ NO")} />
                  <Row label="Minimum Age"  value={phoneResults.minimum_age} />
                </div>
              </Panel>

              <Panel title="RISK">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
                  <Row label="Risk Level"      value={phoneResults.risk_level} />
                  <Row label="Disposable"      value={phoneResults.is_disposable === null ? "—" : (phoneResults.is_disposable ? "✔ YES" : "✘ NO")} />
                  <Row label="Abuse Detected"  value={phoneResults.is_abuse_detected === null ? "—" : (phoneResults.is_abuse_detected ? "✔ YES" : "✘ NO")} />
                  <Row label="Source"          value={phoneResults.source} />
                </div>
              </Panel>
            </>
          )}
        </div>
      )}


      {/* ══════════════════════════════════════════════════════════════════════
          FILE META TAB RESULTS
      ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === "file" && metaResults && (
        <div className="max-w-6xl mx-auto">
          <Panel title={`FILE METADATA — ${metaResults.file_type?.toUpperCase()}`}>
            {metaResults.error ? (
              <p className="text-red-400 text-sm">{metaResults.error}</p>
            ) : (
              <>
                <Row label="URL" value={metaResults.url} />
                <Row label="Type" value={metaResults.file_type} />
                <div className="mt-4">
                  <p className="text-xs opacity-50 mb-3 tracking-widest">EXTRACTED METADATA</p>
                  {Object.entries(metaResults.metadata || {}).map(([k,v]) => v && (
                    <Row key={k} label={k} value={String(v)} />
                  ))}
                </div>
              </>
            )}
          </Panel>
        </div>
      )}


      {/* ══════════════════════════════════════════════════════════════════════
          SCAN HISTORY
      ══════════════════════════════════════════════════════════════════════ */}
      {showHistory && (
        <div className="max-w-6xl mx-auto mt-10">
          <div className="panel p-5 rounded">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-sm tracking-widest opacity-50">▶ SCAN HISTORY ({history.length} scans)</h2>
              <button onClick={() => setShowHistory(false)} className="text-xs opacity-30 hover:opacity-100">✕ CLOSE</button>
            </div>
            {history.length === 0
              ? <p className="text-sm opacity-30">No scans yet</p>
              : <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#00ff4122] text-xs opacity-50 tracking-widest">
                      <th className="text-left pb-3">ID</th>
                      <th className="text-left pb-3">DOMAIN</th>
                      <th className="text-left pb-3">DATE</th>
                      <th className="text-left pb-3">SCORE</th>
                      <th className="text-left pb-3">LEVEL</th>
                      <th className="text-left pb-3">ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map(scan => (
                      <tr key={scan.id} className="border-b border-[#00ff4111] hover:bg-[#00ff4108] transition-all">
                        <td className="py-3 opacity-50">#{scan.id}</td>
                        <td className="py-3 text-[#00ff41]">{scan.domain}</td>
                        <td className="py-3 opacity-50 text-xs">{scan.date}</td>
                        <td className="py-3 font-bold">{scan.risk_score}</td>
                        <td className="py-3">
                          <span className={`text-xs font-bold px-2 py-1 rounded border ${
                            scan.risk_level==="LOW"      ? "text-green-400 border-green-400" :
                            scan.risk_level==="MEDIUM"   ? "text-yellow-400 border-yellow-400" :
                            scan.risk_level==="HIGH"     ? "text-orange-400 border-orange-400" :
                            "text-red-500 border-red-500"
                          }`}>{scan.risk_level}</span>
                        </td>
                        <td className="py-3">
                          <button onClick={async () => {
                            const res = await axios.get(`${API_URL}/api/scan/${scan.id}`)
                            setDomainResults(res.data)
                            setActiveTab("domain")
                            setShowHistory(false)
                            window.scrollTo(0,0)
                          }} className="text-xs border border-[#00ff4133] hover:border-[#00ff41] px-3 py-1 transition-all">
                            VIEW
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>}
          </div>
        </div>
      )}

      {/* FOOTER */}
      <div className="text-center mt-16 opacity-20 text-xs tracking-widest">
        <div className="w-full h-px bg-[#00ff41] mb-4" />
        DEEPFINDER v2.0 — OSINT PLATFORM — FOR AUTHORIZED USE ONLY
      </div>

    </div>
  )
}
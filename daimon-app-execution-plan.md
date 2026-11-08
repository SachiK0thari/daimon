# Private Journaling App: Project Execution Plan

> **Working name:** *Inkwell* (placeholder)
> **Core promise:** Your journal is readable by you, and only you. Not by us, not by our cloud vendors, and not by an attacker who breaches us.
> **Inputs:** typed text, voice dictation, photos of handwritten journal pages.
> **Output:** a deep pattern-analysis dashboard that shows more than sentiment and word clouds.

---

## 0. Guiding Principles (non-negotiable)

1. **Local-first, zero-knowledge.** All journal content is processed and stored on the user's device. If sync exists, the server stores only ciphertext it cannot decrypt.
2. **Analysis runs on-device by default.** No journal text, audio, or image is sent to a third-party AI API. Any cloud processing is opt-in, per-entry, and runs in a HIPAA-eligible environment under a signed BAA.
3. **Minimum necessary.** Collect nothing we don't need. There is no analytics SDK, no ad SDK, and no third-party crash reporter that can see content.
4. **HIPAA as the floor, not the ceiling.** Design to the HIPAA Security Rule even where it does not legally apply, then go further.
5. **Not a diagnostic device.** The app shows patterns. It never diagnoses, and it routes the user to a human when risk signals appear.

---

## 1. Regulatory Reality Check (decide in Week 1)

HIPAA legally applies only if you are a **covered entity** (a provider, health plan, or clearinghouse) or a **business associate** handling PHI for one. A direct-to-consumer journaling app usually is **not** covered by HIPAA. It is instead regulated by:

| Regime | Applies when | Key obligation |
|---|---|---|
| **HIPAA (Privacy, Security, Breach Notification Rules)** | The app is offered by or for a provider or insurer, e.g. therapist-assigned journaling | BAAs, risk analysis, safeguards, breach notification |
| **FTC Health Breach Notification Rule** | Consumer health apps not covered by HIPAA | Notify users and the FTC of unauthorized disclosure, including "sharing" with ad or analytics vendors |
| **FTC Act §5** | Always | No deceptive privacy claims. "HIPAA compliant" marketing must be true. |
| **State laws** (WA My Health My Data Act, CA CMIA/CPRA, CT, NV, etc.) | Users in those states | Consent for consumer health data, deletion rights, no geofencing |
| **GDPR / UK GDPR** | EU or UK users | Art. 9 special-category data, DPIA, explicit consent, DPO |

**Decision to make:** pick the business model first.
- **B2C:** build to HIPAA standards, market as "built to HIPAA Security Rule standards," and comply fully with the FTC HBNR and state laws.
- **B2B2C (clinician portal):** you become a business associate. You need signed BAAs with clinics, a full HIPAA compliance program, and BAAs with every subprocessor.

> **Action:** retain a healthcare privacy attorney before launch. This document is an engineering plan, not legal advice.

---

## 2. System Architecture

```
┌──────────────────────── USER DEVICE (trust boundary) ────────────────────────┐
│                                                                              │
│  Capture ──► Ingestion ──► Normalized Entry ──► Analysis Engine ──► Dashboard│
│  • Text        • On-device ASR (Whisper)            (on-device)              │
│  • Voice       • On-device OCR/HTR                                           │
│  • Photo       • EXIF strip, image redaction                                 │
│                                                                              │
│  Encrypted Store: SQLCipher (AES-256) + encrypted blob store for media       │
│  Keys: Secure Enclave / Android StrongBox, unlocked by biometric + passcode  │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  (optional) E2EE sync: ciphertext only
                                ▼
┌──────────────────────── SYNC SERVER (untrusted by design) ───────────────────┐
│  Stores: encrypted blobs, opaque IDs, minimal account record                 │
│  Cannot read: content, titles, tags, mood scores, analysis results           │
│  Hosted in a HIPAA-eligible environment (AWS/GCP/Azure) under a BAA          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Tech stack (recommended)

| Layer | Choice | Why |
|---|---|---|
| Mobile | **Swift (iOS) + Kotlin (Android)** native, or **React Native / Flutter** with native crypto modules | Native gives the best Secure Enclave/StrongBox access and on-device ML |
| Local DB | **SQLCipher** (SQLite + AES-256) | Battle-tested encrypted DB, with FTS5 for full-text search |
| Speech-to-text | **whisper.cpp** (small/medium, quantized) or Apple Speech with `requiresOnDeviceRecognition = true` | Audio never leaves the device |
| Printed OCR | Apple Vision / Google ML Kit (on-device mode) | Free, fast, offline |
| Handwriting (HTR) | **TrOCR** or a fine-tuned handwriting model, quantized to Core ML / TFLite | Handwritten journals need a dedicated HTR model, not plain OCR |
| NLP / embeddings | Small on-device embedding model (MiniLM-class, ~25–90 MB) + optional small local LLM (1–4B params, quantized) | Semantic patterns without the cloud |
| Crypto | **libsodium** (XChaCha20-Poly1305, Argon2id, X25519) | Modern, misuse-resistant |
| Sync backend | Rust or Go service, Postgres for metadata, S3-compatible object store | Small attack surface |
| Dashboard | Native charts or an embedded local web view (D3/Vega) with **no network permissions** | Rich visuals, offline |

### 2.2 Data model (encrypted at rest)

```
Entry        { id, created_at, local_tz, source: text|voice|photo, body_ciphertext,
               word_count, edited_at, version }
MediaBlob    { id, entry_id, kind: audio|image, ciphertext, nonce, sha256 }
Annotation   { entry_id, type: emotion|topic|entity|distortion|..., span, value, model_version }
DerivedStats { period, metric, value, computed_at }     # all derived data is also encrypted
UserContext  { optional: sleep, meds, cycle, exercise, location_class (never raw GPS) }
```

Derived analysis is often **more sensitive than raw entries** because it can surface inferred depression markers. Encrypt it exactly like the entries.

---

## 3. Security & Privacy Design

### 3.1 Key hierarchy

```
User passcode ──Argon2id──► KEK (Key Encryption Key)
                              │
Device hardware key (Secure Enclave/StrongBox) wraps ─► Master Key (random 256-bit)
                                                           │
                       ┌───────────────┬───────────────────┼────────────────┐
                    DB key        Media key           Sync key        Per-entry keys
```

- The master key never leaves the device unwrapped.
- **Recovery:** a 24-word recovery phrase shown once at setup. We hold **no** escrow key. Losing both the phrase and the device means data loss, and the UI states this clearly.
- **Multi-device:** devices pair over QR code with X25519 key exchange, with no server-side key handling.
- **Key rotation:** supported, re-wrapping per-entry keys without re-encrypting all content.

### 3.2 Device-level protections

- Biometric or passcode lock on every app open, with a configurable auto-lock (default 1 minute).
- **Privacy screen:** blur the app in the task switcher, block screenshots and screen recording on journal screens (`FLAG_SECURE` on Android, overlay on iOS).
- **Duress / panic PIN** (optional): opens an empty decoy journal. This is important for users in abusive situations.
- **Notifications** never contain entry content.
- **Keyboard:** disable third-party keyboard learning on journal fields (secure text entry hints, `IME_FLAG_NO_PERSONALIZED_LEARNING`).
- Exclude the DB from iCloud/Google backups unless the user chooses encrypted export.
- Jailbreak/root detection warns the user (does not block, to avoid security theater).
- Clipboard: auto-clear after 60s when copying from the journal.

### 3.3 Media handling

- **Photos:** capture inside the app only, never write to the camera roll. Strip all EXIF/GPS. Store the original image encrypted, or offer "delete image after transcription."
- **Audio:** recorded to an encrypted temp buffer, transcribed, then deleted by default (user can keep it). Never stored unencrypted on disk.
- Secure deletion: cryptographic erase (destroy the per-entry key) because flash storage can't be reliably overwritten.

### 3.4 Network & backend

- TLS 1.3 only, certificate pinning, HSTS.
- Server holds an opaque user ID, an email (optional; allow anonymous accounts), and ciphertext. No content, no titles, no tags.
- Sync metadata minimization: pad blob sizes to fixed buckets and batch uploads so timing and size don't leak journaling habits.
- No third-party SDKs in the app binary except vetted crypto/ML libraries. Enforce this with an SBOM and a CI check.
- Crash reporting: self-hosted, scrubbed, and opt-in. Stack traces only, never app state.
- Product analytics: none, or privacy-preserving aggregate counts (e.g. differential privacy) with opt-in.

### 3.5 HIPAA Security Rule mapping

| Safeguard | Requirement | Implementation |
|---|---|---|
| **Administrative** | Risk analysis (§164.308(a)(1)) | Annual documented risk assessment + threat model (STRIDE/LINDDUN) |
| | Security officer | Named Security & Privacy Officer |
| | Workforce training | Annual HIPAA + secure coding training |
| | BAAs | With cloud host, email provider, support desk (if they see PHI) |
| | Incident response | Written IR plan, 60-day breach notification workflow, tabletop exercises |
| | Contingency plan | Encrypted backups, disaster recovery tested quarterly |
| **Physical** | Facility/device controls | Cloud provider's certified data centers; company laptops with FDE + MDM |
| **Technical** | Access control | Unique user IDs, auto-logoff, encryption (§164.312(a)) |
| | Audit controls | Server: immutable access logs (no content). Device: local audit log of exports and shares |
| | Integrity | AEAD (Poly1305 tags), signed sync manifests |
| | Authentication | Passkeys/WebAuthn for accounts; MFA for all staff systems |
| | Transmission security | TLS 1.3 + E2EE payloads |

### 3.6 Privacy UX

- Plain-language privacy summary on first launch: what stays on the phone (everything) and what touches our servers (encrypted blobs, if sync is on).
- Granular consent toggles for sync, cloud transcription, and each optional data source (sleep, cycle, etc.).
- One-tap **export** (encrypted archive + readable JSON/Markdown/PDF) and one-tap **delete everything** (local + server, with confirmation).
- Transparency report and public security page (security.txt, bug bounty).

---

## 4. Capture Pipelines

### 4.1 Voice
1. Record (Opus, 16 kHz mono) into an encrypted buffer.
2. Voice activity detection trims silence.
3. On-device Whisper transcription with word-level timestamps.
4. **Prosodic features** extracted locally before the audio is deleted: speech rate, pause frequency and length, pitch variability, energy. These feed the analysis engine (§5.7).
5. The user reviews and edits the transcript, and both versions are kept to measure edit distance (what people revise is a signal too).

### 4.2 Photo of handwritten pages
1. In-app camera with edge detection, perspective correction, and multi-page capture.
2. Line segmentation → HTR model → confidence scores per word.
3. Low-confidence words are highlighted for the user to correct. Corrections fine-tune a **personal handwriting adapter stored on-device**, so accuracy improves over time.
4. **Handwriting features** (optional, experimental): letter size, slant drift, line straightness, pressure proxies from stroke thickness, and crossed-out words. Strikethroughs are captured as annotations, since what someone wrote and crossed out is often the most meaningful text on the page.
5. Date detection: parse handwritten dates so backfilled old journals land on the correct timeline.

---

## 5. The Analysis Engine

The goal is a dashboard that teaches even a psychologist or linguist something new about a person's writing. Standard sentiment is the starting point. Below it are tiers of increasing depth. Every metric shows its evidence (linked excerpts) and its uncertainty.

### Tier 1 — Foundations (MVP)
- Entry frequency calendar heatmap, streaks, time-of-day and day-of-week rhythm.
- Word count trends, vocabulary size, lexical diversity (MTLD, which is more stable than type-token ratio).
- Sentiment and **emotion classification** (beyond positive/negative: joy, sadness, anger, fear, shame, guilt, pride, gratitude, etc.).
- Topic and theme extraction (embeddings + clustering, e.g. BERTopic run locally).
- People, places, and project mentions (on-device NER), plus how mood shifts when each appears.

### Tier 2 — Repetition & Rumination (the "repeated sentences" request)
- **Exact and near-duplicate sentence detection:** MinHash/LSH for near-duplicates, embedding cosine similarity for paraphrases. "You've written some version of *I need to stop putting this off* 23 times since March."
- **Recurring n-grams and phrase templates:** detects the frames people return to ("I should…", "Why do I always…", "If only…").
- **Rumination loops:** topics that recur at high frequency **without movement** in sentiment, verbs, or new information. These are distinguished from **processing**, where a topic recurs but the language progresses (new causal words, resolution language, decreasing emotional intensity).
- **Recurrence plots / Recurrence Quantification Analysis (RQA):** a nonlinear-dynamics technique, borrowed from physics, applied to the sequence of entry embeddings. It quantifies how "stuck" or "chaotic" a period was, using determinism and laminarity scores. Rarely seen in consumer apps or even most clinical practice.
- **Phrase lifecycle:** when a recurring phrase was born, peaked, and died. This often marks the start and end of a life chapter.

### Tier 3 — Psycholinguistic markers (research-grounded)
Each is shown as a trend against the user's own baseline, never against population norms.
- **Pronoun focus:** rates of "I/me/my" vs "we" vs "they." Elevated first-person singular is associated in research with negative affect and inward focus.
- **Absolutist language:** "always," "never," "completely," "nothing." Research links elevated absolutist word rates to anxiety, depression, and suicidal ideation (Al-Mosaiwi & Johnstone, 2018).
- **Cognitive processing words:** "because," "realize," "understand." Increases over time correlate with meaning-making (Pennebaker's expressive-writing research).
- **Temporal orientation:** past vs present vs future tense balance. Shows whether the user tends to dwell, cope, or plan.
- **Agency and locus of control:** active vs passive voice, "I decided" vs "it happened to me," modal verbs ("have to" vs "want to" vs "choose to").
- **Certainty vs hedging:** "definitely" vs "maybe, I guess, sort of."
- **Emotional granularity:** how many distinct emotion words the user uses. Higher granularity is linked to better emotion regulation, and it can be tracked as a skill that grows.
- **Cognitive distortion tagging (CBT):** catastrophizing, mind-reading, should-statements, all-or-nothing, personalization, labeling. Shown with examples and framed as patterns to notice.
- **Negation density and contrast markers** ("but," "however"): these often reveal ambivalence.

### Tier 4 — Dynamics, causality & hidden structure
- **Change-point detection** (Bayesian online change-point, PELT) across emotion and topic time series. "Something shifted around Aug 14," with links to the entries from that week.
- **Lead–lag relationships:** Granger causality or transfer entropy between variables. *Does mentioning your manager predict lower mood 2 days later? Does exercise predict more future-tense language the next day?* Always labeled "associated with," never "causes."
- **Emotional inertia and variability:** the autocorrelation of mood day-to-day. High inertia (emotions that "stick") is a studied affective-dynamics marker. Most people have never seen their own.
- **Emotion transition matrix:** a Markov model showing which emotion tends to follow which ("anger usually turns into guilt within a day, rarely into calm").
- **Seasonality and anniversary effects:** spectral analysis (FFT) and year-over-year alignment show weekly, monthly, and annual cycles, plus **anniversary reactions** (mood dips near the dates of past events the user wrote about).
- **Topic survival analysis:** how long topics persist once raised (Kaplan–Meier curves per theme).
- **Avoidance detection:** topics that were frequent and then abruptly vanished without resolution language, and topics written around but never named (high similarity to a cluster while avoiding its key terms).
- **Contradiction and belief-revision tracking:** natural-language-inference models flag statements that contradict earlier ones ("I'm fine with the move" vs, three weeks later, "I never wanted to move"). Shows how stated beliefs evolve.
- **Semantic drift of key words:** how the meaning of "home," "work," or a person's name changes for the user over time (diachronic embedding shift, a technique from computational linguistics).
- **Social network graph:** people as nodes, co-mention edges, colored by sentiment, with change over time. Shows who appears together and who has quietly disappeared.

### Tier 5 — Cross-modal insights (unique to voice + handwriting)
- **Say–feel gap:** compare the transcript's sentiment with the vocal prosody's arousal. "Your words were positive, but your speech was slower with longer pauses than your baseline." Text-only analysis misses this.
- **Speech-rate and pause trends** across months as a fatigue/energy signal.
- **Handwriting drift:** changes in size, slant, and neatness, correlated with emotion and time of day.
- **Edit and strikethrough analysis:** what the user deletes, revises, or crosses out. Self-censorship patterns are often the most revealing and almost never analyzed.
- **Modality choice as data:** what does the user voice-record vs write by hand vs type? People often speak what they won't write.

### Tier 6 — Narrative & meaning (the professional-grade layer)
- **Narrative arc modeling:** classify life chapters by story shape (redemption, contamination, stable, oscillating), building on McAdams' narrative-identity research.
- **Self-concept map:** extract "I am…" / "I'm the kind of person who…" statements and track how self-descriptions change.
- **Values extraction:** infer what the user repeatedly cares about (autonomy, connection, achievement, security) and flag tension when actions described conflict with stated values.
- **Goal–follow-through tracker:** detect intentions ("tomorrow I'll…") and check whether later entries mention completion. Shows the intention–action gap without judgment.
- **Unasked questions:** questions the user asks themselves repeatedly ("Why can't I…?") are grouped and surfaced, because recurring unanswered questions are prime material for therapy.
- **Personal "trigger → response → outcome" chains:** extracted causal sequences assembled into the user's own recurring behavioral loops.

### 5.8 Making it trustworthy
- **Evidence-first UI:** every insight links to the exact sentences that produced it.
- **Confidence and n:** show sample size and confidence; hide insights below a threshold.
- **Personal baselines:** compare users to their own history, not to population norms.
- **Model cards:** each metric has a "how this works / limitations / research behind it" panel.
- **User feedback loop:** "This is accurate / not accurate" refines local models.
- **Clinician export (opt-in):** a PDF summary a user can choose to share with their therapist, with citations to methods.

### 5.9 Clinical safety
- On-device risk detection for self-harm or suicidal language (with conservative thresholds and a validated lexicon + classifier).
- On detection: a gentle, non-alarming card with crisis resources (988 Suicide & Crisis Lifeline in the US, localized elsewhere). **No data is sent anywhere automatically.**
- Never label a user with a diagnosis. Language like "patterns that some people find worth discussing with a professional."
- Clinical advisory board (a psychologist + a psychiatrist) reviews every metric and its wording before release.
- Assess whether any feature makes the product an FDA **Software as a Medical Device**. Keep claims in the general-wellness category unless you deliberately pursue clearance.

---

## 6. Dashboard Design

| Panel | Content |
|---|---|
| **Overview** | This week vs your baseline: mood, energy, top themes, one highlighted insight |
| **Timeline** | Scrollable life timeline with change-points, chapters, and anniversaries marked |
| **Repetition Lab** | Recurring sentences and phrases, rumination vs processing classifier, recurrence plot |
| **Language Lens** | Pronouns, absolutist words, tense, agency, certainty, emotional granularity |
| **Emotion Dynamics** | Transition matrix, inertia, variability, time-of-day/weekday patterns |
| **People & Places** | Relationship network graph, mood by person, appearance and disappearance |
| **Connections** | Lead–lag discoveries ("X tends to precede Y by N days"), with evidence |
| **Voice & Hand** | Say–feel gap, speech rate, handwriting drift, crossed-out text |
| **Story** | Narrative arcs, self-concept changes, values, intention–follow-through |
| **Ask your journal** | Local semantic search + optional local LLM Q&A ("When did I last feel like this?") |

Design notes: calm visual language, no gamified shame (no "you broke your streak"), dark mode, accessibility (WCAG 2.2 AA, screen-reader-friendly charts with text summaries).

---

## 7. Execution Roadmap

### Phase 0 — Foundations (Weeks 1–4)
- [ ] Legal: business model decision (B2C vs B2B2C), privacy counsel, privacy policy draft
- [ ] Threat model (STRIDE + LINDDUN privacy threats) and HIPAA risk analysis v1
- [ ] Appoint Security & Privacy Officer; write security policies
- [ ] Choose stack; set up repo, CI/CD, SBOM generation, dependency scanning, secret scanning
- [ ] Clinical advisory board recruited

### Phase 1 — Secure Core MVP (Weeks 5–12)
- [ ] Encrypted local store (SQLCipher), key hierarchy, biometric lock, recovery phrase
- [ ] Text entry, search (FTS on decrypted-in-memory index)
- [ ] On-device voice → text
- [ ] Photo capture → printed OCR + handwriting HTR with correction UI
- [ ] Tier 1 analysis + basic dashboard
- [ ] Export and delete-all
- [ ] Internal security review #1

### Phase 2 — Deep Analysis (Weeks 13–22)
- [ ] Tier 2 (repetition, rumination, RQA) and Tier 3 (psycholinguistics)
- [ ] Tier 4 (change-points, lead–lag, transition matrices, seasonality, contradictions)
- [ ] Evidence-linked insight UI, model cards, confidence thresholds
- [ ] Crisis-language safety layer, reviewed by clinicians
- [ ] Closed beta (50–100 users) with informed consent; validate insight accuracy with user feedback

### Phase 3 — Sync, Cross-modal, Narrative (Weeks 23–32)
- [ ] E2EE multi-device sync; backend in a HIPAA-eligible environment with a BAA
- [ ] Tier 5 cross-modal (prosody, handwriting, strikethroughs)
- [ ] Tier 6 narrative and values layer
- [ ] Optional local LLM "Ask your journal"
- [ ] Clinician export PDF

### Phase 4 — Hardening & Launch (Weeks 33–40)
- [ ] **External penetration test** (mobile + API + crypto review by a specialist firm)
- [ ] Third-party audit: SOC 2 Type I (then Type II), HITRUST if selling to health systems
- [ ] Bug bounty program launched
- [ ] Incident response tabletop exercise
- [ ] App store privacy labels (must accurately state "Data Not Collected" where true)
- [ ] Public launch

### Ongoing
- Quarterly pentests on major releases, annual risk analysis, dependency patching SLA (critical: 72h)
- Model accuracy audits, including bias checks across dialects, languages, and handwriting styles
- Transparency report

---

## 8. Team

| Role | Count | Notes |
|---|---|---|
| Mobile engineers (iOS/Android) | 2–3 | Crypto + on-device ML experience |
| ML/NLP engineer | 1–2 | Model quantization, HTR, psycholinguistic NLP |
| Data scientist (time series) | 1 | Change-point, causality, RQA |
| Backend/security engineer | 1 | Sync server, infra, IR |
| Product designer | 1 | Calm, trauma-informed UX |
| Security & Privacy Officer | 0.5–1 | Can be fractional early |
| Clinical advisors | 2 (part-time) | Psychologist, psychiatrist |
| Privacy counsel | External | |

---

## 9. Testing & Verification

- **Security:** SAST/DAST in CI, MobSF scans, OWASP MASVS Level 2 + resiliency (R) as the target, crypto review, fuzzing of sync protocol and import parsers.
- **Privacy:** network traffic audits on every release (proxy the app; assert no unexpected hosts and no plaintext). Automated test: journal content must never appear in any outbound request.
- **ML quality:** WER benchmarks for ASR across accents; CER for handwriting; annotated gold sets for emotion, distortion, and rumination; precision tracked for the crisis classifier with a strong bias toward recall.
- **Usability:** test with real journalers, including older users, users with dyslexia, and users of handwritten journals.
- **Red-team the insights:** could any insight be harmful if seen by an abusive partner? Is any wording stigmatizing?

---

## 10. Key Risks & Mitigations

| Risk | Mitigation |
|---|---|
| On-device models too slow or large for older phones | Tiered models; run heavy analysis while charging and idle; feature-gate by device class |
| Handwriting accuracy poor for messy scripts | Personal adapter fine-tuning; always-editable transcripts |
| Users lose recovery phrase | Clear onboarding, optional printed recovery kit, optional encrypted export reminders |
| Insights misread as diagnosis | Wellness framing, clinician-reviewed wording, model cards |
| Legal exposure from "HIPAA compliant" claims | Counsel-approved marketing language; actual compliance program |
| Coercive access (abusive partner, device seizure) | Duress PIN, decoy journal, hidden app icon option, quick-lock gesture |
| Supply-chain attack via dependency | Minimal deps, pinned versions, SBOM, reproducible builds |

---

## 11. Definition of Done for v1

- No journal content, audio, image, or derived insight ever leaves the device unencrypted, verified by network audit.
- External pentest has zero open critical/high findings.
- Users can capture by text, voice, and handwritten photo, offline.
- Dashboard ships Tiers 1–4 with evidence links and confidence indicators.
- Crisis safety flow reviewed and signed off by clinical advisors.
- Privacy policy, risk analysis, IR plan, and BAAs (where applicable) are complete.

---

*This plan is an engineering roadmap. Have legal counsel confirm your HIPAA, FTC, and state-law obligations before launch.*

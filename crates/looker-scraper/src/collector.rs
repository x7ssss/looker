use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use crate::error::ScraperError;
use crate::extractor::{CandidateExtractor, CandidateProxy};
use crate::sources::{ProxySource, DEFAULT_SOURCES};

pub struct ProxyScraper {
    client: Client,
    extractor: Arc<CandidateExtractor>,
    sources: Vec<ProxySource>,
    concurrency_limit: usize,
}

impl Default for ProxyScraper {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyScraper {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Looker/0.1")
            .build()
            .expect("Failed to build HTTP client for scraper");

        Self {
            client,
            extractor: Arc::new(CandidateExtractor::new()),
            sources: DEFAULT_SOURCES.to_vec(),
            concurrency_limit: 8,
        }
    }

    pub fn with_sources(mut self, sources: Vec<ProxySource>) -> Self {
        self.sources = sources;
        self
    }

    pub fn with_concurrency(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit;
        self
    }

    /// Fetches all configured public sources concurrently and returns unique candidates.
    pub async fn scrape_all(&self) -> Result<Vec<CandidateProxy>, ScraperError> {
        info!("Starting public proxy scrape across {} sources", self.sources.len());

        let sem = Arc::new(Semaphore::new(self.concurrency_limit));
        let mut tasks = Vec::with_capacity(self.sources.len());

        for source in &self.sources {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = self.client.clone();
            let source = source.clone();
            let extractor = Arc::clone(&self.extractor);

            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                debug!("Fetching source '{}' from {}", source.name, source.url);

                match client.get(source.url).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            if let Ok(text) = resp.text().await {
                                let mut extracted = extractor.extract(&text);
                                if let Some(proto) = source.default_proto {
                                    for c in &mut extracted {
                                        if c.proto.is_none() {
                                            c.proto = Some(proto);
                                        }
                                    }
                                }
                                debug!(
                                    "Source '{}' yielded {} candidates",
                                    source.name,
                                    extracted.len()
                                );
                                return extracted;
                            }
                        } else {
                            error!(
                                "Source '{}' returned HTTP status {}",
                                source.name,
                                resp.status()
                            );
                        }
                    }
                    Err(e) => {
                        error!("Failed to fetch source '{}': {}", source.name, e);
                    }
                }
                Vec::new()
            }));
        }

        let mut candidate_set = HashSet::new();
        for task in tasks {
            if let Ok(candidates) = task.await {
                for c in candidates {
                    candidate_set.insert(c);
                }
            }
        }

        let result: Vec<CandidateProxy> = candidate_set.into_iter().collect();
        info!("Scraped {} unique valid public proxy candidates", result.len());
        Ok(result)
    }
}

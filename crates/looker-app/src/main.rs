#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use looker_gateway::{GatewayConfig, ProxyGateway};
use looker_geo::GeoResolver;
use looker_pool::ProxyPool;
use looker_scraper::{CheckerConfig, ProxyChecker, ProxyScraper};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::webview::NewWindowResponse;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use tokio_util::sync::CancellationToken;
use tracing::info;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("looker=info,looker_app=info,looker_gateway=info")
        .init();

    info!("Starting Looker Desktop Shell (Tauri v2)...");

    let cancel_token = CancellationToken::new();
    let pool = Arc::new(ProxyPool::new().with_cooldown(Duration::from_secs(60)));
    let geo_resolver = Arc::new(GeoResolver::empty());

    let cancel_token_setup = cancel_token.clone();
    let pool_setup = Arc::clone(&pool);
    let geo_setup = Arc::clone(&geo_resolver);

    tauri::Builder::default()
        .on_window_event(|window, event| {
            // Prevent window close from killing background proxy/downloads
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(move |app| {
            // 1. Spawn background proxy scraper & validation engine
            let pool_scrape = Arc::clone(&pool_setup);
            let scraper_cancel = cancel_token_setup.child_token();
            let geo_clone = Arc::clone(&geo_setup);

            tauri::async_runtime::spawn(async move {
                let scraper = ProxyScraper::new();
                let checker_config = CheckerConfig {
                    max_concurrency: 500,
                    timeout: Duration::from_secs(5),
                    connect_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(10),
                    target_authority: "ipv4.icanhazip.com:443".to_string(),
                };
                let checker = Arc::new(ProxyChecker::with_config(
                    geo_clone,
                    checker_config,
                    None,
                ));

                // Priority Warm-Boot Seeding: load previous survivors from out/proxies.json
                let warm_file = std::path::Path::new("out/proxies.json");
                let warm_candidates = looker_scraper::load_warm_boot_candidates(warm_file);
                if !warm_candidates.is_empty() {
                    info!(
                        "[LOOKER APP] Warm-boot: priority-checking {} cached survivor proxies from {}...",
                        warm_candidates.len(),
                        warm_file.display()
                    );
                    let _ = checker
                        .check_all_streaming(warm_candidates, Arc::clone(&pool_scrape))
                        .await;
                    let stats = pool_scrape.stats();
                    info!(
                        "[LOOKER APP WARM-BOOT COMPLETE] {} healthy proxies available immediately (avg latency: {} ms)",
                        stats.healthy_proxies, stats.avg_latency_ms
                    );
                    let _ = pool_scrape.export_to_dir(std::path::Path::new("out"));
                }

                loop {
                    if scraper_cancel.is_cancelled() {
                        break;
                    }

                    info!("[LOOKER APP] Running periodic candidate scrape & validation...");
                    if let Ok(candidates) = scraper.collect_all().await {
                        let mut all_to_check = candidates;
                        let quarantined = pool_scrape.list_quarantined();
                        if !quarantined.is_empty() {
                            for q in quarantined {
                                all_to_check.push(looker_scraper::CandidateProxy::new(q.addr, Some(q.proto)));
                            }
                        }

                        if !all_to_check.is_empty() {
                            let _ = checker
                                .check_all_streaming(all_to_check, Arc::clone(&pool_scrape))
                                .await;
                        }

                        // Hard 3-strike prune
                        let pruned = pool_scrape.prune_dead();
                        if pruned > 0 {
                            tracing::debug!("[LOOKER APP] Pruned {} dead proxies with >= 3 failures", pruned);
                        }

                        // Periodic Clean Disk Sync
                        let out_dir = std::path::Path::new("out");
                        if let Err(e) = pool_scrape.export_to_dir(out_dir) {
                            tracing::warn!("[LOOKER APP] Periodic disk sync failed: {}", e);
                        } else {
                            info!(
                                "[LOOKER APP] Periodic disk sync: synchronized {} healthy proxies to {}/ (zero dead clutter)",
                                pool_scrape.healthy_count(),
                                out_dir.display()
                            );
                        }
                    }

                    tokio::select! {
                        _ = scraper_cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(900)) => {}
                    }
                }
            });

            // 2. Spawn local proxy gateway daemon on 127.0.0.1:8080
            let gateway_config = GatewayConfig {
                bind_addr: "127.0.0.1:8080".parse().unwrap(),
                max_retries: 4,
                connect_timeout: Duration::from_secs(6),
                buffer_size: 16384,
            };
            let gateway = ProxyGateway::new(gateway_config, Arc::clone(&pool_setup));
            let gw_cancel = cancel_token_setup.child_token();

            tauri::async_runtime::spawn(async move {
                info!("[LOOKER APP] Gateway listener launching on http://127.0.0.1:8080");
                if let Err(e) = gateway.run_with_cancellation(gw_cancel).await {
                    tracing::error!("[LOOKER APP] Gateway server error: {}", e);
                }
            });

            // 3. Setup System Tray menu
            let show_i = MenuItem::with_id(app, "show", "Show Looker", true, None::<&str>)?;
            let live_i = MenuItem::with_id(app, "live", "Open live.txt", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit Looker", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &live_i, &quit_i])?;

            let cancel_tray = cancel_token_setup.clone();
            let pool_tray = Arc::clone(&pool_setup);

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("LOOKER // Rotating Proxy Gateway & Downloader")
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "live" => {
                        let _ = opener::open("http://127.0.0.1:8080/live.txt");
                    }
                    "quit" => {
                        info!("[LOOKER APP] Quit requested from tray menu. Shutting down...");
                        cancel_tray.cancel();
                        let out_dir = std::path::Path::new("out");
                        let _ = pool_tray.export_to_dir(out_dir);
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                });

            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }

            let _tray = tray_builder.build(app)?;

            let _builder = WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External("http://127.0.0.1:8080/ui".parse().unwrap()),
            )
            .title("LOOKER // Network Control & Proxy Gateway")
            .inner_size(1280.0, 800.0)
            .min_inner_size(900.0, 600.0)
            .center()
            .resizable(true)
            .background_color(tauri::window::Color(9, 9, 11, 255))
            .on_new_window(|url, _features| {
                let _ = opener::open(url.as_str());
                NewWindowResponse::Deny
            })
            .build()?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Error while running Looker desktop application");
}

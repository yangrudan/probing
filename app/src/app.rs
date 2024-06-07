use leptonic::prelude::*;
use leptos::*;
use leptos_meta::{provide_meta_context, Meta, Stylesheet, Title};
use leptos_router::*;

use crate::{
    error_template::{AppError, ErrorTemplate},
    pages::overview::Overview,
    pages::profiler::Profiler,
};

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Meta name="charset" content="UTF-8"/>
        // <Meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <Meta name="theme-color" content="#e66956"/>

        <Stylesheet id="leptos" href="/pkg/leptonic-template-ssr.css"/>
        <Stylesheet href="https://fonts.googleapis.com/css?family=Roboto&display=swap"/>

        <Title text="Probe"/>

        <Root default_theme=LeptonicTheme::default()>
            <HeaderBar/>
            <Box style="width: 90%; margin-left: 5%;  margin-right: 5%">
                <Router fallback=|| {
                    let mut outside_errors = Errors::default();
                    outside_errors.insert_with_default_key(AppError::NotFound);
                    view! { <ErrorTemplate outside_errors/> }
                }>
                    <Routes>
                        <Route path="" view=|| view! { <Overview/> }/>
                        <Route path="profiler" view=|| view! { <Profiler/> }/>
                    </Routes>
                </Router>
            </Box>
        </Root>
    }
}

#[component]
pub fn HeaderBar() -> impl IntoView {
    view! {
        <Box style="width: 100%;">
            <AppBar
                height=Size::Px(36)
                style="z-index: 1; background: var(--brand-color); color: white; align=left"
            >
                <Stack
                    orientation=StackOrientation::Horizontal
                    spacing=Size::Em(1.0)
                    style="margin-left: 2em"
                >
                    <H1 style="color: white;">"Probe"</H1>
                    <Button on_click=move |_| {
                        let navigate = leptos_router::use_navigate();
                        navigate("/", Default::default());
                    }>
                        <Icon icon=icondata::AiHomeOutlined/>
                        "Overview"
                    </Button>
                    <Button on_click=move |_| {
                        let navigate = leptos_router::use_navigate();
                        navigate("/snapshot", Default::default());
                    }>
                        <Icon icon=icondata::CgDebug/>
                        "Snapshot"
                    </Button>
                    <Button on_click=move |_| {
                        let navigate = leptos_router::use_navigate();
                        navigate("/profiler", Default::default());
                    }>
                        <Icon icon=icondata::CgPerformance/>
                        "Profiler"
                    </Button>
                </Stack>

                <Stack
                    orientation=StackOrientation::Horizontal
                    spacing=Size::Em(1.0)
                    style="margin-right: 2em"
                >
                    <a
                        href="https://github.com/reiase/probe"
                        style=" text-decoration: none; color:inherit"
                    >
                        <Icon icon=icondata::BsGithub/>
                    </a>
                    <Icon icon=icondata::BsPower/>
                </Stack>
            </AppBar>
        </Box>
    }
}
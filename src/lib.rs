use error_chain::error_chain;
use http::{HeaderMap, StatusCode};
use once_cell::sync::Lazy;
use std::{collections::HashMap, ffi::OsStr, fs, ops::Deref, path::Path, process::Command};

use filenamify::filenamify;
use log::info;
use reqwest::Url;
use scraper::{error::SelectorErrorKind, selector::Selector, Html};
use serde_derive::Deserialize;
use titlecase::titlecase;
use toml::Table;

error_chain! {
    foreign_links {
        Toml(toml::de::Error);
        Reqwest(reqwest::Error);
        Io(std::io::Error);
        Regex(regex::Error);
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct SiteConfig {
    pub name: String,
    pub save_path: String,
    pub format: String,
    pub source: SourceConfig,
    pub tags: HashMap<String, TagConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TagConfig {
    pub css_selector: String,
    pub default: Option<String>,
    pub regex: Option<String>,
    pub minimum: Option<usize>,
    pub attr: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SourceConfig {
    pub attr: String,
    pub css_selector: String,
}
trait TitleCase {
    fn titlecase(&self) -> String;
}

impl TitleCase for String {
    fn titlecase(&self) -> String {
        titlecase(self)
    }
}

#[derive(Debug)]
pub struct ImageUrl {
    url: Url,
    ext: String,
}

impl ImageUrl {
    fn new(url: Url) -> Self {
        let filename = url.path_segments().unwrap().last().unwrap().to_string();
        let ext = Path::new(&filename)
            .extension()
            .and_then(OsStr::to_str)
            .map(|x| x.to_string());

        // TODO: use proper error handling
        assert!(ext.is_some());

        Self {
            url,
            ext: ext.unwrap(),
        }
    }
}

impl Deref for ImageUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.url
    }
}

#[derive(Debug)]
pub struct Website {
    pub cfg: SiteConfig,
    pub url: ImageUrl,
    pub tags: HashMap<String, Vec<String>>,
}

impl Website {
    pub fn new(cfg: SiteConfig, url: ImageUrl, tags: HashMap<String, Vec<String>>) -> Self {
        Self { cfg, url, tags }
    }
}

impl Website {
    fn url(&self) -> Url {
        self.url.clone()
    }

    fn filename(&self) -> Result<String> {
        let reg = handlebars::Handlebars::new();

        let mut tags = self.tags.clone();

        tags.insert(String::from("w"), vec![self.cfg.name.clone()]);

        let tags = tags
            .iter()
            .map(|(k, v)| (k, v.join(", ")))
            .collect::<HashMap<_, _>>();

        let rendered = reg
            .render_template(&self.cfg.format, &tags)
            .chain_err(|| "Failed to render template")?;
        let formatted = html_escape::decode_html_entities(&rendered);
        let filename = filenamify(formatted);

        Ok(filename)
    }

    pub fn from(input: Vec<u8>, cfg: SiteConfig) -> Result<Website> {
        // Create a string representation of the response
        let response = String::from_utf8(input).chain_err(|| "Could not convert input to utf-8")?;

        // Parse the response into an HTML document
        let document = scraper::Html::parse_document(&response);

        let mut tag_list = HashMap::new();

        // Iterate over the tags in the config
        for (k, v) in cfg.tags.iter() {
            let mut tags = match get_tag_list_attr(
                &document,
                Selection::from(&v.css_selector, v.attr.as_deref()).unwrap(),
            ) {
                Some(x) => x,
                None => {
                    if v.required {
                        return Err(format!("No tags found for {:#}", k).into());
                    } else {
                        vec![v.default.clone().unwrap()]
                    }
                }
            };

            if let Some(regex) = &v.regex {
                let re = regex::Regex::new(regex).chain_err(|| "Failed to create regex")?;

                tags = tags
                    .into_iter()
                    .map(|x| {
                        re.captures(&x)
                            .and_then(|x| x.get(0))
                            .map(|x| x.as_str().to_string())
                            .unwrap_or(x)
                    })
                    .collect::<Vec<_>>();
            }

            tags = tags
                .iter()
                .map(|x| x.trim().to_string().titlecase())
                .collect::<Vec<_>>();

            tags.sort();
            tags.dedup();

            tag_list.insert(k.to_string(), tags);
        }

        let src = match get_tag_list_attr(
            &document,
            Selection::from(&cfg.source.css_selector, Some(&cfg.source.attr)).unwrap(),
        ) {
            Some(x) => match x.first() {
                Some(x) => x.clone(),
                None => {
                    return Err("No source found".into());
                }
            },
            None => {
                return Err("No source found".into());
            }
        };

        let image = Website::new(
            cfg,
            ImageUrl::new(Url::parse(&src).chain_err(|| "Could not parse url")?),
            tag_list,
        );

        Ok(image)
    }

    pub fn download(&self) -> Result<()> {
        let output = query(&self.url())?;

        let filename = self.filename()?;

        let output_dir =
            Path::new(&self.cfg.save_path).join(format!("{}.{}", &filename, &self.url.ext));
        // .with_extension(&self.url.ext);

        if is_duplicate_file(&output_dir, &output) {
            return Err("Duplicate file".into());
        }

        info!("Writing file {:#} to {:?}", filename, output_dir);

        fs::write(output_dir, output).chain_err(|| "Failed to write file")?;

        Ok(())
    }
}

enum SelectorType {
    Query(Selector, String),
    Plain(Selector),
}

impl SelectorType {
    fn from(selector: &str) -> std::result::Result<Self, SelectorErrorKind> {
        if !selector.contains('?') {
            return Selector::parse(selector).map(Self::Plain);
        }

        if let Some((x, y)) = selector.split_once('?') {
            return Selector::parse(x).map(|x| Self::Query(x, y.trim().into()));
        }

        todo!()
    }
}

enum Selection {
    Attr(Vec<SelectorType>, String),
    Html(Vec<SelectorType>),
}

impl Selection {
    fn from<'a>(
        selector: &'a str,
        attr: Option<&str>,
    ) -> std::result::Result<Self, SelectorErrorKind<'a>> {
        let selectors = selector
            .split('|')
            .map(|x| x.trim())
            .map(SelectorType::from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if let Some(attr) = attr {
            Ok(Self::Attr(selectors, attr.into()))
        } else {
            Ok(Self::Html(selectors))
        }
    }
}

fn get_tag_list_attr(document: &Html, selection: Selection) -> Option<Vec<String>> {
    match selection {
        Selection::Attr(selectors, attr) => selectors.iter().find_map(|s| match s {
            SelectorType::Query(selector, query) => {
                let mut iter = document.select(selector).peekable();
                iter.peek()?;
                iter.filter(|x| x.inner_html().contains(query))
                    .filter(|x| x.value().attr(&attr).is_some())
                    .map(|x| {
                        x.value()
                            .attr(&attr)
                            .map(|x| html_escape::decode_html_entities(x.trim()).into())
                    })
                    .collect::<Option<Vec<_>>>()
            }
            SelectorType::Plain(selector) => {
                let mut iter = document.select(selector).peekable();
                iter.peek()?;
                iter.filter(|x| x.value().attr(&attr).is_some())
                    .map(|x| {
                        x.value()
                            .attr(&attr)
                            .map(|x| html_escape::decode_html_entities(x.trim()).into())
                    })
                    .collect::<Option<Vec<_>>>()
            }
        }),
        Selection::Html(selectors) => selectors.iter().find_map(|s| match s {
            SelectorType::Query(selector, query) => {
                let mut iter = document.select(selector).peekable();
                iter.peek()?;
                iter.filter(|x| x.inner_html().contains(query))
                    .map(|x| Some(html_escape::decode_html_entities(x.inner_html().trim()).into()))
                    .collect::<Option<Vec<_>>>()
            }
            SelectorType::Plain(selector) => {
                let mut iter = document.select(selector).peekable();
                iter.peek()?;
                iter.filter(|x| !x.inner_html().is_empty())
                    .map(|x| Some(html_escape::decode_html_entities(x.inner_html().trim()).into()))
                    .collect::<Option<Vec<_>>>()
            }
        }),
    }
}

fn is_duplicate_file(path: &Path, new_file: &Vec<u8>) -> bool {
    let file = match fs::File::open(path) {
        Ok(x) => x,
        Err(_) => return false,
    };

    if let Ok(x) = file.metadata() {
        if x.len() as usize != new_file.len() {
            return false;
        }
    };

    let bytes = match fs::read(path) {
        Ok(x) => x,
        Err(_e) => {
            return false;
        }
    };

    if md5::compute(bytes) != md5::compute(new_file) {
        return false;
    }

    true
}

pub fn load_config(url: &Url, path: &str) -> Result<SiteConfig> {
    let cfg_path = Path::new(path);

    let cfg_str = fs::read_to_string(cfg_path).chain_err(|| "Failed to read config file")?;

    let cfg: Table = cfg_str
        .parse()
        .chain_err(|| "Failed to parse TOML config")?;

    let domain = match url.domain() {
        Some(x) => x.split_once('.').map(|(d, _)| d).unwrap_or_default(),
        None => return Err("Invalid URL: no domain found".into()),
    };

    let domain_cfg = match cfg["website"][domain].as_table() {
        Some(x) => x,
        None => return Err(format!("No configuration found for {domain}").into()),
    };

    let res: SiteConfig = toml::from_str(domain_cfg.to_string().as_str())
        .chain_err(|| "Failed to interpret as SiteConfig")?;

    Ok(res)
}

pub fn query(url: &Url) -> Result<Vec<u8>> {
    info!("Calling {:#}", url);

    request_internal(url).or_else(|_| request_external(url))
}

fn request_external(url: &Url) -> Result<Vec<u8>> {
    Ok(Command::new("curl")
        .arg(url.as_str())
        .output()
        .chain_err(|| "Failed to run curl")?
        .stdout)
}

fn request_internal(url: &Url) -> Result<Vec<u8>> {
    static REQ_CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(|| {
        // Spoof headers to make the website think we are a browser ( •̀ᴗ•́ )و ̑̑
        let mut headers = HeaderMap::new();
        headers.insert(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
                .parse()
                .unwrap(),
        );
        headers.insert("Accept-Language", "en-US,en;q=0.5".parse().unwrap());
        // headers.insert("Accept-Encoding", "gzip, deflate, br".parse().unwrap());
        headers.insert(
            "Sec-Ch-Ua",
            "\"Chromium\";v=\"115\", \" Not/A)Brand\";v=\"99\""
                .parse()
                .unwrap(),
        );
        headers.insert("Upgrade-Insecure-Requests", "1".parse().unwrap());

        // Create a client with headers
        reqwest::blocking::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .default_headers(headers)
            .build()
            .unwrap()
    });

    let result = REQ_CLIENT.get(url.as_str()).send()?;

    match result.status() {
        StatusCode::OK => Ok(result.bytes()?.to_vec()),
        _ => Err("Error".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn test_not_duplicate_files_path() {
        let testfile = fs::read("./tests/shared/testfile1.jpeg").expect("Unable to read file");

        let result = super::is_duplicate_file(
            std::path::Path::new("./tests/shared/testfile.jpeg"),
            &testfile,
        );

        assert!(!result, "Files are equal");
    }

    #[test]
    fn test_not_duplicate_files_length() {
        let testfile = fs::read("./tests/shared/testfile1.jpeg").expect("Unable to read file");

        let result = super::is_duplicate_file(
            std::path::Path::new("./tests/shared/testfile2.jpeg"),
            &testfile,
        );

        assert!(!result, "Files are equal");
    }

    #[test]
    fn test_not_duplicate_files_hash() {
        let testfile =
            fs::read("./tests/shared/filelengthfile1.test.txt").expect("Unable to read file");

        let result = super::is_duplicate_file(
            std::path::Path::new("./tests/shared/filelengthfile2.test.txt"),
            &testfile,
        );

        assert!(!result, "Files are equal");
    }

    #[test]
    fn test_is_duplicate_files() {
        let testfile = fs::read("./tests/shared/testfile1.jpeg").expect("Unable to read file");

        let result = super::is_duplicate_file(
            std::path::Path::new("./tests/shared/testfile1.jpeg"),
            &testfile,
        );

        assert!(result, "Files are not equal");
    }

    #[test]
    fn test_get_tag_list_attr_success() {
        let file = fs::read_to_string("./tests/shared/wallhaven.test.html").unwrap();

        let html = scraper::Html::parse_document(&file);

        let ss = get_tag_list_attr(
            &html,
            Selection::from("#wallpaper-short-url-copy", Some("value")).unwrap(),
        )
        .unwrap();

        assert_eq!(ss.first().unwrap(), "https://whvn.cc/exwgmr");
    }

    #[test]
    fn test_get_tag_list_attr_fail() {
        let file = fs::read_to_string("./tests/shared/wallhaven.test.html").unwrap();

        let html = scraper::Html::parse_document(&file);

        let ss = get_tag_list_attr(
            &html,
            Selection::from("#wallpaper-short-url", Some("value")).unwrap(),
        );

        assert!(ss.is_none());
    }

    #[test]
    fn test_get_tag_list_success() {
        let file = fs::read_to_string("./tests/shared/wallhaven.test.html").unwrap();

        let html = scraper::Html::parse_document(&file);

        let ss = get_tag_list_attr(
            &html,
            Selection::from("#tags > li > a:nth-child(1)", None).unwrap(),
        )
        .unwrap();

        assert_eq!(
            ss,
            vec![
                "digital art",
                "rain",
                "plant pot",
                "trees",
                "animals",
                "looking away"
            ]
        );
    }

    #[test]
    fn test_get_tag_list_fail() {
        let file = fs::read_to_string("./tests/shared/wallhaven.test.html").unwrap();

        let html = scraper::Html::parse_document(&file);

        let ss = get_tag_list_attr(
            &html,
            Selection::from("#tags > li > a:nth-child(2)", None).unwrap(),
        );

        assert!(ss.is_none());
    }
}

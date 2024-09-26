use anyhow::Result;

use headless_chrome::Browser;

fn hello_trustify() -> Result<()> {
    let browser = Browser::default()?;
    let tab = browser.new_tab()?;
    let element = tab
        .navigate_to("http://localhost:8080")?
        .wait_until_navigated()?
        .find_element(".pf-v5-c-page__drawer")?; // Looking for a specific CSS class name.

    let inner_divs = element.find_elements("div")?;

    println!("{}", inner_divs.len());
    assert_eq!(inner_divs.len(), 5); // Whatever test here means the page loaded fine.

    Ok(())
}

fn main() -> Result<()> {
    hello_trustify()
}
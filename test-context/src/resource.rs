use futures::future::BoxFuture;

#[derive(Default)]
pub struct ResourceStack {
    resources: Vec<Box<dyn TestResource>>,
}

pub trait TestResource: Send + 'static {
    fn drop(self: Box<Self>) -> BoxFuture<'static, ()>;
}

pub trait TestResourceExt {
    fn then(self, other: impl TestResource) -> Box<dyn TestResource>;
}

impl<R: TestResource> TestResourceExt for R {
    fn then(self, other: impl TestResource) -> Box<dyn TestResource> {
        Box::new(vec![
            Box::new(self) as Box<dyn TestResource>,
            Box::new(other) as Box<dyn TestResource>,
        ])
    }
}

impl TestResourceExt for Box<dyn TestResource> {
    fn then(self, other: impl TestResource) -> Box<dyn TestResource> {
        Box::new(vec![self, Box::new(other) as Box<dyn TestResource>])
    }
}

impl ResourceStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn drop(mut self) {
        while let Some(r) = self.resources.pop() {
            TestResource::drop(r).await;
        }
    }

    pub fn then(mut self, r: impl TestResource) -> Self {
        self.resources.push(Box::new(r));
        self
    }
}

impl TestResource for Vec<Box<dyn TestResource>> {
    fn drop(mut self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            while let Some(r) = self.pop() {
                r.drop().await;
            }
        })
    }
}

impl<R: TestResource> From<R> for ResourceStack {
    fn from(value: R) -> Self {
        ResourceStack {
            resources: vec![Box::new(value)],
        }
    }
}

impl From<Box<dyn TestResource>> for ResourceStack {
    fn from(value: Box<dyn TestResource>) -> Self {
        ResourceStack {
            resources: vec![value],
        }
    }
}

impl From<()> for ResourceStack {
    fn from(_: ()) -> Self {
        ResourceStack::new()
    }
}

#[allow(drop_bounds)]
pub fn defer(d: impl Drop + Send + 'static) -> impl TestResource {
    struct Defer<D: Drop + Send + 'static>(D);

    impl<D: Drop + Send + 'static> TestResource for Defer<D> {
        fn drop(self: Box<Self>) -> BoxFuture<'static, ()> {
            let value = self;
            Box::pin(async move {
                tokio::task::spawn_blocking(move || drop(value))
                    .await
                    .expect("failed to await spawn_blocking");
            })
        }
    }

    Defer(d)
}

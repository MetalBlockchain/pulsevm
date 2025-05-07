pub trait Indexed<T> {
    fn primary_key(&self) -> T;
}

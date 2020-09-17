use rand::prelude::Rng;

fn main() {
  let mut rng = rand::thread_rng();
  let random_num: i32 = rng.gen_range(-100, 101);

  println!("Here's a random number: {}", random_num);
}
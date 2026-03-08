use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ironwood_rs::BloomFilter;

fn bench_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_add");
    for n in [1usize, 8, 32, 64] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let keys: Vec<[u8; 32]> = (0..n).map(|i| {
                let mut k = [0u8; 32];
                k[0] = i as u8;
                k[1] = (i >> 8) as u8;
                k
            }).collect();
            b.iter(|| {
                let mut bloom = BloomFilter::new();
                for k in &keys {
                    bloom.add(black_box(k));
                }
                black_box(bloom)
            });
        });
    }
    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_encode");

    // sparse filter (few elements)
    let mut sparse = BloomFilter::new();
    for i in 0u8..8 {
        sparse.add(&[i; 32]);
    }

    // dense filter (many elements)
    let mut dense = BloomFilter::new();
    for i in 0u16..256 {
        let mut k = [0u8; 32];
        k[0] = i as u8;
        k[1] = (i >> 8) as u8;
        dense.add(&k);
    }

    group.bench_function("sparse_8_elements", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(1024);
            black_box(&sparse).encode(&mut out);
            black_box(out)
        })
    });

    group.bench_function("dense_256_elements", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(1024);
            black_box(&dense).encode(&mut out);
            black_box(out)
        })
    });

    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_decode");

    let mut sparse = BloomFilter::new();
    for i in 0u8..8 {
        sparse.add(&[i; 32]);
    }
    let mut sparse_encoded = Vec::new();
    sparse.encode(&mut sparse_encoded);

    let mut dense = BloomFilter::new();
    for i in 0u16..256 {
        let mut k = [0u8; 32];
        k[0] = i as u8;
        k[1] = (i >> 8) as u8;
        dense.add(&k);
    }
    let mut dense_encoded = Vec::new();
    dense.encode(&mut dense_encoded);

    group.bench_function("sparse_8_elements", |b| {
        b.iter(|| {
            black_box(BloomFilter::decode(black_box(&sparse_encoded)))
        })
    });

    group.bench_function("dense_256_elements", |b| {
        b.iter(|| {
            black_box(BloomFilter::decode(black_box(&dense_encoded)))
        })
    });

    group.finish();
}

fn bench_base_hashes(c: &mut Criterion) {
    c.bench_function("bloom_base_hashes", |b| {
        let key = [0xABu8; 32];
        b.iter(|| {
            black_box(BloomFilter::base_hashes(black_box(&key)))
        })
    });
}

criterion_group!(benches, bench_add, bench_encode, bench_decode, bench_base_hashes);
criterion_main!(benches);

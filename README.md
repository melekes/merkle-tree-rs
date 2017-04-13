# Merkle Tree implemented in Rust programming language

*Spoiler: this is one of the variations of Merkle tree. Concrete
implementations serve different objectives and therefore can greatly differ in
detail.*

Merkle Tree is a binary tree, which nodes values are the hash of the
concatenated values of their descendants hashes.

Main article: https://en.wikipedia.org/wiki/Merkle_tree

### Storage format

A binary tree is stored in a vector in breadth-first order. That is, starting
with the root we go from left to right at every level.

```
    1
  2   3
 4 5 6 7
```

Vector:

```
[1 2 3 4 5 6 7]
```

While building a tree, if there is an odd number of nodes at the given level,
the last node will be duplicated. Otherwise, the tree won't be complete. And we
need it to be complete in order to "2i 2i+1" schema to work.

### Defence against potential attacks

To defend against the second-preimage attack, when we calculate the hash we
prepend data with 0x00 - for leaves, 0x01 - for internal nodes.

By default, we use SHA256. But you can pass your hash function (for example,
double SHA256).

## Usage

Let's say you have a file. You split it into 100 blocks and build a tree.

```rust
use merkle_tree::MerkleTree;

let t: MerkleTree = MerkleTree::build(&blocks);
```

block could be anything, as long as it implements [`AsBytes`] trait. In order
to encode the numbers, you can use [byteorder
library](https://github.com/BurntSushi/byteorder). If the block is an array of
bytes, you don't have to do anything.

As we mentioned earlier, you can pass your hash function:

```
use merkle_tree::MerkleTree;

let t: MerkleTree = MerkleTree::build_with_hasher(&blocks, MyAwesomeHasher::new());
```

Then you somehow make a secure copy of the root hash.

```
t.root_hash();
```

You can now copy leaves from any source.

```
t.leaves();
```

If we verify that those leaves sum up to the `root_hash`, we can use them to
verify the blocks. Blocks could be received and checked one by one.

```
let t: MerkleTree = MerkleTree::build_from_leaves(&leaves);
assert_eq!(secure_copy_of_root_hash, t.root_hash());

assert!(t.verify(block_index, &block));
```

where `block_index` - index of a block (starts at 0).

## Decision log

### Почему бинарное дерево?

Ни в одном источнике не говориться, сколько дочерних узлов должно быть у предка.
Обычно выбирают 2. Получается, нам нужно знать только хэш соседнего узла, чтобы
проверить поддерево. И так вплоть до корневого узла. На каждом уровне нам нужен
лишь сосед справа (или слева). Это конечно, если нам требуется проверять log(N)
хэшей на пути к корню.

```
    1
  2   3
```

### Почему дерево упаковано в массив?

Я пробовал разные решения. В конце первого дня у меня было стандартное бинарное дерево (tag: 0.1.0).

```
struct Node
{
    hash: Vec<u8>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}
```

Потом добавил к нему массив ссылок на нижние элементы (используя Rc).

```
struct Node
{
    hash: Vec<u8>,
    left: Option<Rc<Node>>,
    right: Option<Rc<Node>>,
}

struct MerkleTree {
    root: Node,
    leaves: Vec<Rc<Node>>,
}
```

Главное преимущество такого дерева - возможность выкачивать ветви и
проверять их в отсутствии полного дерева. НО тут я столкнулся с
противоречием в статье на Wikipedia: мы можем выкачивать ветви, но мы не
доверяем дереву пока оно не сходится к root hash. Что же получается? Мы
выкачиваем ветви и надеемся на лучшее?

Не знаю что сказать. Мне оно не нравилось и оно было излишне сложным.
Конечно, я посмотрел другие реализации, но все они были либо чересчур
абстрактными (не решали никакую проблему, не имели явного API), либо были
написаны неудачно.

Единственная понравившаяся версия была на C++
(https://codetrips.com/2016/06/19/implementing-a-merkle-tree-in-c/). На нее я
наткнулся в конце второго дня. Но и она не была без недостатков. Я не говорю о
shared_ptr на данные (указатель на данные в дереве; в Rust такое можно сделать
только через raw_pointers). Я говорю о том, что неясно как верифицируется
дерево на другой стороне (когда мы его скопировали для проверки данных). Ведь
там указателей не будет! Да и блоки данных мы получаем не все сразу.

Я не сразу пришел к последней версии. Довольно много пришлось подумать и
поэкспериментировать. Возможно, стоило продумать все моменты до реализации.
Но тогда я бы не узнал столько о Rust.

**Плюсы конечной реализации**

1. Легкость обхода дерева
2. Отсуствие указателей в обе стороны (parent <-> child)
3. Легкость сериализации - это же просто массив

(1) Чтобы достать родителя элемента, нужно лишь разделить индекс текущего узла
пополам: `5 / 2 = 2`. Индекс левого дочернего узла - `2i`, правого - `2i+1`.
Получаем легкость обхода дерева как от корня к дочерним элементам, так и от
узлов нижнего уровня к корню.

(3) Чтобы достать все узлы нижнего уровня, мы просто достаем `count_leaves`
последних элементов.

**Минусы конечной реализации**

1. Математика (2i, 2i+1) все же посложнее простого следования по указателям
   (`e.left...`).
2. Дерево должно быть полным (кроме последнего уровня), чтобы математика
   работала. Порой приходится добавлять копии элементов.

**Возможные улучшения**

1. Предоставить реализации AsBytes для большего кол-ва типов.
2. В методе `build_upper_level` складывать новые узлы не в новый массив, а в
   `nodes` (in-place).
3. Разобраться с "rust cannot infer type for _" (`let _t: MerkleTree`).
4. Сериализация/десериализация отдельным модулем
5. Удобный интерфейс для пушетествия по дереву (`root().left().right()`) -
   Builder pattern.

## Development

### Step 1. Create development environment

You will need [docker engine](https://docs.docker.com/engine/installation/) if
you want to develop this library inside a container. If you already have rust
on your computer and fine with downloading some dependencies, feel free to skip
this step.

```
$ make create_dev_env
$ make run_shell
```

### Step 2. Build & test

```
$ cargo build --features "dev"
$ cargo test
```

### Step 3. Benchmark

```
$ cargo bench --features "dev"
```


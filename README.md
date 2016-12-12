# Merkle Tree implemented in Rust programming language

*Спойлер: это одна из версий того, как может быть реализовано дерево Меркла.
Конкретные реализации служат различным задачам и поэтому могут сильно
различаться в деталях.*

Дерево Меркла - дерево, у которого в узле находится хэш, полученный путем
соединения хэшей дочерних элементов.

Основная статья: https://en.wikipedia.org/wiki/Merkle_tree

### Формат хранения

Бинарное дерево располагается в векторе в порядке breadth-first. Начиная с
корневого узла идем слева направо на каждом уровне.

```
    1
  2   3
 4 5 6 7
```

Массив:

```
[1 2 3 4 5 6 7]
```

При формировании дерева, если на промежуточных уровнях нечетное количество
узлов, то последний узел дублируется. Иначе, дерево будет не полным (complete
binary tree). Условие полноты необходимо для описанной выше схемы хранения "2i
2i+1".

### Защита от потенциальных атак

Чтобы защититься от атаки нахождения второго прообраза, в момент вычисления хэша
к узлу добавляется: 0x00 - если он на нижнем уровне, 0x01 - если промежуточный или
корневой.

По умолчанию для хэширования используется SHA256. Но можно передать свою
реализацию (например, double SHA256).

## Использование

Допустим у вас есть файл. Вы разбиваете его на 100 кусков и строите дерево.

```rust
use merkle_tree::MerkleTree;

let t: MerkleTree = MerkleTree::build(&blocks);
```

В качестве блока может быть что угодно, до тех пор пока оно реализует trait
`AsBytes`. Для кодирования чисел есть библиотека
https://github.com/BurntSushi/byteorder . Если это уже массив байтов, ничего
делать не требуется.

Как уже упоминалось выше, можно передать свою хэш-функцию:

```
use merkle_tree::MerkleTree;

let t: MerkleTree = MerkleTree::build(&blocks, MyAwesomeHasher::new());
```

Дальше вы каким-то магическим образом безопасно копируете root hash.

```
t.root_hash();
```

После этого можно скопировать элементы нижнего уровня (небезопасно, из любого
источника).

```
t.leaves();
```

Если они "сходятся" к root hash, то считаем их подлинными.

```
let t: MerkleTree = MerkleTree::build_from_leaves(&leaves);
assert_eq!(secure_copy_of_root_hash, t.root_hash());
```

Осталось лишь запустить копирование нашего файла и по получении очередного блока
выполнять проверку:

```
assert!(t.verify(block_index, &block));
```

где `block_index` - индекс блока (начиная с 0).

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
    leaves: Vec<Rc<Node>>
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
(https://codetrips.com/2016/06/19/implementing-a-merkle-tree-in-c/). На нее
я наткнулся в конце второго дня. Но и она не была без недостатков. Я не
говорю о shared_ptr на данные (указатель на данные в дереве; в Rust такое
можно сделать только через raw_pointers). Я говорю о том, что неясно как
верифицируется дерево на другой стороне. Ведь там указателей не будет! Да и
блоки данных мы получаем не все сразу.

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

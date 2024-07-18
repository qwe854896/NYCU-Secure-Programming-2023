<?php
isset($_GET['source']) && die(!show_source(__FILE__));

class Magic
{
    function cast($spell)
    {
        echo "<script>alert('MAGIC, $spell!');</script>";
    }
}

// Useless class?
class Caster
{
    public $cast_func = 'intval';
    function __construct($cast_func) {
    	$this->cast_func = $cast_func;
    }
    function cast($val)
    {
        return ($this->cast_func)($val);
    }
}


class Cat
{
    public $magic;
    public $spell;
    function __construct($magic, $spell)
    {
        // $this->magic = new Magic();
        $this->magic = $magic;
        $this->spell = $spell;
    }
    function __wakeup()
    {
        echo "Cat Wakeup!\n";
        $this->magic->cast($this->spell);
    }
}

if (isset($_GET['spell'])) {
    $cat = new Cat($_GET['spell']);
} else if (isset($_COOKIE['cat'])) {
    echo "Unserialize...\n";
    $cat = unserialize(base64_decode($_COOKIE['cat']));
} else {
    $cat = new Cat(new Caster("system"), "ls /");
    $result = serialize($cat);
    $encoded_result = base64_encode($result);
}
?>
<pre>
This is your 🐱:
<?php var_dump($cat) ?>

This is the serialized result:
<?php var_dump($result) ?>

This is the encoded result:
<?php var_dump($encoded_result) ?>
</pre>

<p>Usage:</p>
<p>/?source</p>
<p>/?spell=the-spell-of-your-cat</p>

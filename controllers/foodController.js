const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const { toNumber, isUuid } = require('../utils/validation');

// -------------------- GET /foods --------------------
exports.getAllFoods = async (req, res) => {
  try {
    const [foods] = await db.query(
      'SELECT * FROM food_items WHERE available = 1 ORDER BY category, name'
    );
    res.json(foods);
  } catch (err) {
    console.error('Get foods error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /foods --------------------
exports.addFood = async (req, res) => {
  const { name, price, description, category } = req.body;

  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Name is required' });
  }

  const priceValue = toNumber(price);
  if (priceValue === null || priceValue <= 0) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }

  try {
    const foodId = uuidv4();
    await db.query(
      `INSERT INTO food_items (id, name, price, description, category, available, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [foodId, name.trim(), priceValue, description || '', category || 'General', true]
    );

    const [newFood] = await db.query('SELECT * FROM food_items WHERE id = ?', [foodId]);
    res.status(201).json(newFood[0]);

  } catch (err) {
    console.error('Add food error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- PUT /foods/:id (Update food) --------------------
exports.updateFood = async (req, res) => {
  const { id } = req.params;
  const { name, price, description, category, available } = req.body;

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid food id' });
  }

  try {
    // Check if food exists
    const [food] = await db.query('SELECT id FROM food_items WHERE id = ?', [id]);
    if (food.length === 0) {
      return res.status(404).json({ error: 'Food item not found' });
    }

    // Build dynamic update query
    const fields = [];
    const values = [];
    if (name !== undefined) {
      if (typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({ error: 'Name must be a non-empty string' });
      }
      fields.push('name = ?');
      values.push(name.trim());
    }
    if (price !== undefined) {
      const priceValue = toNumber(price);
      if (priceValue === null || priceValue <= 0) {
        return res.status(400).json({ error: 'Price must be a positive number' });
      }
      fields.push('price = ?');
      values.push(priceValue);
    }
    if (description !== undefined) { fields.push('description = ?'); values.push(description); }
    if (category !== undefined) { fields.push('category = ?'); values.push(category); }
    if (available !== undefined) {
      if (typeof available !== 'boolean' && available !== 0 && available !== 1) {
        return res.status(400).json({ error: 'available must be a boolean' });
      }
      fields.push('available = ?');
      values.push(available ? 1 : 0);
    }
    fields.push('updated_at = NOW()');

    if (fields.length === 1) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    await db.query(
      `UPDATE food_items SET ${fields.join(', ')} WHERE id = ?`,
      [...values, id]
    );

    const [updatedFood] = await db.query('SELECT * FROM food_items WHERE id = ?', [id]);
    res.json(updatedFood[0]);

  } catch (err) {
    console.error('Update food error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- DELETE /foods/:id (Soft delete – set unavailable) --------------------
exports.deleteFood = async (req, res) => {
  const { id } = req.params;

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid food id' });
  }

  try {
    const [result] = await db.query(
      'UPDATE food_items SET available = 0, updated_at = NOW() WHERE id = ?',
      [id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Food item not found' });
    }
    res.json({ message: 'Food item marked as unavailable' });
  } catch (err) {
    console.error('Delete food error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- GET /foods/:id --------------------
exports.getFoodById = async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid food id' });
  }

  try {
    const [foods] = await db.query(
      'SELECT * FROM food_items WHERE id = ? AND available = 1',
      [id]
    );

    if (foods.length === 0) {
      return res.status(404).json({ error: 'Food item not found' });
    }

    return res.json(foods[0]);
  } catch (err) {
    console.error('Get food by id error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// routes/cart.js
const express = require("express");
const router = express.Router();
const { body, validationResult } = require("express-validator");
const winston = require("winston"); // Assuming winston is accessible or passed
// NOTE: We will access 'db' via 'req.db' which is set in app.js for better practice.
// For now, let's assume logger, isAuthenticated, authorizeRole, ROLES are available in the scope
// or you adjust the imports below.

// --- Logger setup (ensure this matches your app.js setup, or import it) ---
const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: "error.log", level: "error" }),
        new winston.transports.File({ filename: "combined.log" }),
    new winston.transports.Console({
        format: winston.format.combine(winston.format.colorize(), winston.format.simple())
    })
    ],
});

// --- Constants for Roles (ensure this matches your app.js setup, or import it) ---
const ROLES = {
    ADMIN: 'admin',
    USER: 'user',
    PHARMACY: 'pharmacy'
};

// --- Auth Middleware (ensure this matches your app.js setup, or import it) ---
// You might need to import these from a central middleware file if they are not globally available.
// For now, copied from your main app.js for this file to be runnable independently if needed.
const isAuthenticated = (req, res, next) => {
    if (!req.session.user) {
        logger.warn(`Unauthorized access attempt to ${req.originalUrl}`);
        return res.redirect("/login");
    }
    next();
};

const authorizeRole = (roles = []) => {
    if (typeof roles === 'string') {
        roles = [roles];
    }
    return (req, res, next) => {
        if (!req.session.user) {
            logger.warn(`Unauthorized access: No user session for ${req.originalUrl}`);
            return res.redirect("/login");
        }
        if (roles.length && !roles.includes(req.session.user.role)) {
            logger.warn(`Access denied for user '${req.session.user.email}' (role: ${req.session.user.role}) to ${req.originalUrl}`);
            return res.status(403).render("403.ejs", { user: res.locals.user, message: "Access Denied: You do not have permission to view this page." });
        }
        next();
    };
};

// ===== Cart Routes =====

// 1. Add to Cart (POST)
router.post("/cart/add", isAuthenticated, authorizeRole(ROLES.USER), [
    body('medicine_id').isInt({ gt: 0 }).withMessage('Invalid medicine ID.'),
    body('quantity').isInt({ gt: 0 }).withMessage('Quantity must be a positive integer.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn(`Validation errors on POST /cart/add: ${JSON.stringify(errors.array())}`);
        return res.status(400).send(`Invalid input: ${errors.array().map(e => e.msg).join(', ')}`);
    }

    const { medicine_id, quantity } = req.body;
    const userId = req.session.user.id;
    const db = req.db; // Access db from req object (set in app.js)

    try {
        // Check medicine availability
        const [medResults] = await db.execute(
            "SELECT availability, name, price FROM medicines WHERE id = ?",
            [medicine_id]
        );

        if (medResults.length === 0) {
            return res.status(404).send("Medicine not found.");
        }

        const medicine = medResults[0];

        // Check if medicine is already in cart
        const [cartItem] = await db.execute(
            "SELECT quantity FROM cart_items WHERE user_id = ? AND medicine_id = ?",
            [userId, medicine_id]
        );

        let newQuantityInCart = quantity;
        if (cartItem.length > 0) {
            newQuantityInCart += cartItem[0].quantity; // Add to existing quantity
        }

        if (newQuantityInCart > medicine.availability) {
            return res.status(400).send(`Cannot add ${quantity} of ${medicine.name}. Total in cart would be ${newQuantityInCart}, but only ${medicine.availability} are available.`);
        }

        if (cartItem.length > 0) {
            // Update existing cart item
            await db.execute(
                "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND medicine_id = ?",
                [newQuantityInCart, userId, medicine_id]
            );
            logger.info(`User ${userId} updated quantity of medicine ${medicine_id} in cart to ${newQuantityInCart}`);
        } else {
            // Add new cart item
            await db.execute(
                "INSERT INTO cart_items (user_id, medicine_id, quantity) VALUES (?, ?, ?)",
                [userId, medicine_id, quantity]
            );
            logger.info(`User ${userId} added medicine ${medicine_id} with quantity ${quantity} to cart.`);
        }

        res.redirect("/findMedicine"); // Or to the cart page
    } catch (err) {
        logger.error("Error adding/updating cart item", err);
        res.status(500).send("Failed to add item to cart.");
    }
});

// 2. View Cart (GET)
router.get("/cart", isAuthenticated, authorizeRole(ROLES.USER), async (req, res) => {
    const userId = req.session.user.id;
    const db = req.db; // Access db from req

    try {
        const query = `
            SELECT ci.id AS cart_item_id, ci.quantity,
                   m.id AS medicine_id, m.name AS medicine_name, m.price, m.availability, m.category,
                   p.name AS pharmacy_name, p.address AS pharmacy_address
            FROM cart_items ci
            JOIN medicines m ON ci.medicine_id = m.id
            JOIN pharmacies p ON m.pharmacy_id = p.id
            WHERE ci.user_id = ?
            ORDER BY p.name, m.name
        `;
        const [cartItems] = await db.execute(query, [userId]);

        // Calculate total price for each item and overall total
        let totalCartPrice = 0;
        const itemsWithTotals = cartItems.map(item => {
            const itemTotalPrice = item.quantity * item.price;
            totalCartPrice += itemTotalPrice;
            return {
                ...item,
                itemTotalPrice: itemTotalPrice
            };
        });

        res.render("cart.ejs", { cartItems: itemsWithTotals, totalCartPrice });
    } catch (err) {
        logger.error("Error fetching cart items", err);
        res.status(500).send("Failed to load cart.");
    }
});

// 3. Update Cart Item Quantity (POST)
router.post("/cart/update/:cart_item_id", isAuthenticated, authorizeRole(ROLES.USER), [
    body('quantity').isInt({ gt: 0 }).withMessage('Quantity must be a positive integer.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn(`Validation errors on POST /cart/update: ${JSON.stringify(errors.array())}`);
        return res.status(400).send(`Invalid quantity: ${errors.array().map(e => e.msg).join(', ')}`);
    }

    const { cart_item_id } = req.params;
    const { quantity } = req.body;
    const userId = req.session.user.id;
    const db = req.db;

    try {
        // Verify cart item belongs to user and get medicine availability
        const [cartDetails] = await db.execute(
            `SELECT ci.quantity AS current_cart_quantity, m.availability, m.name, m.id AS medicine_id
             FROM cart_items ci
             JOIN medicines m ON ci.medicine_id = m.id
             WHERE ci.id = ? AND ci.user_id = ?`,
            [cart_item_id, userId]
        );

        if (cartDetails.length === 0) {
            return res.status(404).send("Cart item not found or does not belong to you.");
        }

        const { availability, name: medicineName, medicine_id: mid } = cartDetails[0];

        if (quantity > availability) {
            return res.status(400).send(`Requested quantity (${quantity}) for ${medicineName} is not available. Only ${availability} left.`);
        }

        await db.execute(
            "UPDATE cart_items SET quantity = ? WHERE id = ? AND user_id = ?",
            [quantity, cart_item_id, userId]
        );
        logger.info(`User ${userId} updated cart item ${cart_item_id} (medicine ${mid}) quantity to ${quantity}`);
        res.redirect("/cart");
    } catch (err) {
        logger.error("Error updating cart item quantity", err);
        res.status(500).send("Failed to update cart item quantity.");
    }
});

// 4. Remove from Cart (POST)
router.post("/cart/remove/:cart_item_id", isAuthenticated, authorizeRole(ROLES.USER), async (req, res) => {
    const { cart_item_id } = req.params;
    const userId = req.session.user.id;
    const db = req.db;

    try {
        // Optional: Verify cart item belongs to user before deleting
        const [check] = await db.execute(
            "SELECT id FROM cart_items WHERE id = ? AND user_id = ?",
            [cart_item_id, userId]
        );

        if (check.length === 0) {
            logger.warn(`User ${userId} tried to remove cart item ${cart_item_id} which doesn't belong to them.`);
            return res.status(403).send("Cart item not found or you don't have permission.");
        }

        await db.execute(
            "DELETE FROM cart_items WHERE id = ? AND user_id = ?",
            [cart_item_id, userId]
        );
        logger.info(`User ${userId} removed cart item ${cart_item_id}`);
        res.redirect("/cart");
    } catch (err) {
        logger.error("Error removing item from cart", err);
        res.status(500).send("Failed to remove item from cart.");
    }
});

// 5. Checkout (Process Cart to Orders) (POST)
router.post("/cart/checkout", isAuthenticated, authorizeRole(ROLES.USER), async (req, res) => {
    const userId = req.session.user.id;
    const db = req.db; // Access db from req

    const connection = await db.getConnection(); // Get a connection from the pool for transaction
    try {
        await connection.beginTransaction();

        // 1. Fetch all items from the user's cart
        // Add FOR UPDATE to prevent race conditions during checkout
        const [cartItems] = await connection.execute(
            `SELECT ci.quantity, m.id AS medicine_id, m.availability, m.name, m.pharmacy_id, m.price
             FROM cart_items ci
             JOIN medicines m ON ci.medicine_id = m.id
             WHERE ci.user_id = ? FOR UPDATE`,
            [userId]
        );

        if (cartItems.length === 0) {
            await connection.rollback();
            return res.status(400).send("Your cart is empty.");
        }

        // 2. Validate availability and create orders
        const ordersToCreate = [];
        for (const item of cartItems) {
            if (item.quantity > item.availability) {
                await connection.rollback();
                logger.warn(`Checkout failed for user ${userId}: Not enough availability for medicine ${item.name}. Requested: ${item.quantity}, Available: ${item.availability}`);
                return res.status(400).send(`Not enough stock for ${item.name}. Only ${item.availability} available.`);
            }
            ordersToCreate.push({
                medicine_id: item.medicine_id,
                quantity: item.quantity,
                pharmacy_id: item.pharmacy_id,
                price: item.price // Store price at time of order for historical accuracy
            });
        }

        // 3. Insert into orders table and update medicine availability
        for (const order of ordersToCreate) {
            // Insert into orders
            // Assuming your orders table has columns: user_id, medicine_id, quantity, status, and potentially price_at_order
            await connection.execute(
                "INSERT INTO orders (user_id, medicine_id, quantity, status) VALUES (?, ?, ?, ?)",
                [userId, order.medicine_id, order.quantity, 'pending']
            );

            // Update medicine availability
            await connection.execute(
                "UPDATE medicines SET availability = availability - ? WHERE id = ?",
                [order.quantity, order.medicine_id]
            );
        }

        // 4. Clear the user's cart
        await connection.execute(
            "DELETE FROM cart_items WHERE user_id = ?",
            [userId]
        );

        await connection.commit();
        logger.info(`User ${userId} successfully checked out cart and created orders.`);
        res.redirect("/orders"); // Redirect to the user's orders page
    } catch (err) {
        await connection.rollback(); // Rollback transaction on any error
        logger.error("Error during checkout process", err);
        res.status(500).send("Failed to process your order. Please try again.");
    } finally {
        connection.release(); // Release the connection back to the pool
    }
});

module.exports = router;
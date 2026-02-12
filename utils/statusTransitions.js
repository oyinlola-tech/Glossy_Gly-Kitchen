/**
 * Allowed order status transitions
 * Key: current status
 * Value: array of allowed next statuses
 */
const allowedTransitions = {
  pending: ['confirmed', 'cancelled'],
  confirmed: ['preparing', 'cancelled'],
  preparing: ['out_for_delivery', 'cancelled'],
  out_for_delivery: ['completed'],
  completed: [],
  cancelled: [],
};

/**
 * Check if a status transition is allowed
 * @param {string} currentStatus
 * @param {string} newStatus
 * @returns {boolean}
 */
const isTransitionAllowed = (currentStatus, newStatus) => {
  return allowedTransitions[currentStatus]?.includes(newStatus) || false;
};

module.exports = {
  allowedTransitions,
  isTransitionAllowed,
};
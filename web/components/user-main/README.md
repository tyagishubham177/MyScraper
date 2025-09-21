# User Mode UI Notes

## Legacy Experience Summary
- A full-screen animated gradient with particle effects served as the background.
- A centered header displayed the Amul logo alongside the "Product subscription Tracking" title.
- The main content area opened with a large welcome message that shrank after animation, followed by the subscription list injected into `#user-subscriptions-container`.
- A floating action button in the bottom-right corner opened an off-canvas settings drawer that grouped account actions, pincode update controls, and feedback links.
- Supporting modals and loaders managed profile updates (display name modal) and async states (`#global-loader`).

## Modern Redesign Goals
- Preserve all functional hooks (IDs, modules, and flows) while refreshing the layout hierarchy.
- Introduce a card-based, responsive dashboard with distinct zones for greetings, subscriptions, and quick tips.
- Strengthen visual clarity through refined typography, softened glassmorphism accents, and accessible color contrasts.
- Elevate interaction affordances for settings, pincode updates, and feedback entry points.

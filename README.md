This part of the read me is the humans (diegos) thoughts.

This app was created with the idea of making a combo list and trainer for granblue fantasy versus rising as it does not currently have one. 
The goal was to make a combo trainer as close to the ones implemented in other games with a little more ui friendlyness for the user, namely the option to display inputs to thier liking and the ability to train them in the same menu, which this app does.

This app focuses on a few characters im aware of just so i can check the quality of the app itself via playing the game. However during a full release all characters would be ideal, including letting users sumbit thier own combos as desired, since combos themselves arent really known till a user submit them.

The overall design is to remain simply so that it wouldnt be annoying to have along the game but also complex enough to make sure it does what its set out too. With more pages I think you could make this even more user friendly and have more features.


This section of the read me is done by claude in order to see its thought process.

# GBVSR Combo Guide - Design Documentation

## Overview
A comprehensive web application for learning and practicing combos in Granblue Fantasy Versus Rising (GBVSR). Built as a single-page HTML application with embedded CSS and JavaScript for maximum portability and ease of use.

## Core Design Philosophy

### **Single-Page Architecture**
- **Decision**: Built as one HTML file with embedded assets
- **Reasoning**: Easy deployment, no build process, works offline, simple hosting
- **Benefit**: Users can save locally and access anywhere without dependencies

### **Character-Centric Design**
- **Decision**: Multi-character support with character selection as primary navigation
- **Reasoning**: GBVSR players typically focus on one main character but want to explore others
- **Implementation**: Character cards with descriptions help users understand archetypes before diving into combos

## Visual Design Choices

### **Color Scheme**
- **Primary**: Deep purples and golds inspired by Nier's aesthetic
- **Reasoning**: Creates cohesive visual identity while remaining readable
- **Accessibility**: High contrast ratios maintained throughout

### **D-Pad Visual Inputs**
- **Decision**: Custom 3x3 grid D-pad visuals alongside traditional notation
- **Reasoning**: Matches Dustloop's authentic fighting game documentation style
- **Benefit**: Visual learners can see directional inputs clearly, beginners understand motion inputs better

### **Dual Display System**
- **Decision**: Toggle between visual inputs and text notation
- **Reasoning**: Accommodates both visual learners and players who prefer traditional FGC notation
- **Flexibility**: Users can show both simultaneously or choose their preferred format

## Interaction Design

### **Play Animation System**
- **Decision**: Realistic timing-based animations that highlight inputs sequentially
- **Reasoning**: Helps users understand combo rhythm and timing
- **Implementation**: Each input has individual timing values for authentic feel

### **Favorites & Practice Tracking**
- **Decision**: Session-based storage (no localStorage)
- **Reasoning**: Browser compatibility and privacy - no persistent data collection
- **UX**: Visual feedback with colored borders for favorited/practiced combos

### **Progressive Disclosure**
- **Decision**: Hide controls until character is selected
- **Reasoning**: Reduces visual clutter and guides user flow
- **Benefit**: Clear hierarchy - character selection first, then combo filtering

## Technical Decisions

### **No External Dependencies**
- **Decision**: Pure HTML/CSS/JavaScript with no frameworks
- **Reasoning**: Maximum compatibility, fast loading, no version conflicts
- **Tradeoff**: More verbose code but better reliability

### **Responsive Grid System**
- **Decision**: CSS Grid for combo cards with auto-fill columns
- **Reasoning**: Adapts to any screen size without media query complexity
- **Mobile**: Single column on mobile, multi-column on desktop

### **Embedded Combat Data**
- **Decision**: Hard-coded combo data rather than external API
- **Reasoning**: Ensures app works offline, no server dependencies
- **Source**: Based on authentic Dustloop frame data and notation

## Removed Features

### **Advanced Statistics Tracking**
- **Removed**: Complex practice statistics and success rates
- **Reason**: Session-only data made detailed tracking less valuable
- **Simplified**: Basic favorites/practiced flags provide sufficient user feedback

### **User Accounts/Persistence**
- **Removed**: User login and cloud save functionality
- **Reason**: Keeps app simple and privacy-focused
- **Alternative**: Users can bookmark combos by favoriting during sessions

### **Real-time Data**
- **Removed**: Live updates from fighting game databases
- **Reason**: Combo data is relatively static, offline functionality prioritized
- **Benefit**: Faster loading, no network dependencies

## Content Strategy

### **Character Selection**
- **Curated**: 4 diverse characters representing different archetypes
- **Coverage**: Rushdown (Vikala), Grappler (Galleon), Unique (Nier), Heavy (Siegfried)
- **Expandable**: Data structure supports easy addition of new characters

### **Combo Difficulty Progression**
- **Beginner**: Basic BnB combos for learning fundamentals
- **Intermediate**: Practical combos with character-specific mechanics
- **Advanced/Expert**: High-damage and specialized situational combos

### **Authentic Notation**
- **Standard**: Uses established FGC notation (236, 214, j., c., etc.)
- **Consistency**: Maintains Dustloop standards for familiar feel
- **Accessibility**: Combines with visual D-pad for broader understanding

## Future Considerations
The modular data structure and clean separation of concerns allow for easy expansion of characters, combos, and features while maintaining the core simplicity that makes the app effective for learning and practice.

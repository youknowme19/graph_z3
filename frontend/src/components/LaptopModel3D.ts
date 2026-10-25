import * as THREE from 'three';
import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader.js';

export interface LaptopController {
  group: THREE.Group;
  update: (elapsedTime: number, progress: number, mouseX: number, mouseY: number, isDarkTheme?: boolean) => void;
  dispose: () => void;
  isLoaded: boolean;
  screenTexture: THREE.CanvasTexture | null;
  redPointLight: THREE.PointLight;
  keyLight: THREE.DirectionalLight;
  rimRight: THREE.DirectionalLight;
  rimLeft: THREE.DirectionalLight;
}

/**
 * Creates the high-tech dynamic canvas texture for the Laptop Screen.
 * Renders live disassembly, Z3 invariant solver telemetry, GNN risk waveforms,
 * and high-contrast crimson / cyan cybernetic indicators.
 */
function createLaptopScreenCanvas() {
  const canvas = document.createElement('canvas');
  canvas.width = 1024;
  canvas.height = 640;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;
  texture.magFilter = THREE.LinearFilter;

  const codeSnippets = [
    '0x7F454C46 · ELF64_X86_64_BINARY',
    'claripy.BVS("sym_payload", 256)',
    'Z3_SOLVER: (check-sat) -> SAT',
    'SageConv_GNN(40_DIM) [P=0.984 CRITICAL]',
    '0x10000051c : STRNCPY_CHK_VIOLATION',
    'UNSAT_PRUNING: 99.72% PATHS REDUCED',
    'REPRODUCER_SYNTHESIS: 40_BYTES GENERATED',
    'STACK_FRAME_CANARY_OVERWRITTEN',
    'VEX_IR_LIFT: t0 = GET:I64(rbp - 0x20)',
    '0x4141414141414141_INVARIANT_BREACH',
    'MEMCPY_BOUNDS_ENFORCEMENT_FAILED',
    'VERIFIED_EXPLOIT_POC_CONFIRMED',
  ];

  let scanlineY = 0;
  let codeScroll = 0;

  const update = (elapsedTime: number) => {
    // 1. Deep Obsidian Terminal Background
    ctx.fillStyle = '#08090e';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Subtle technical grid
    ctx.strokeStyle = 'rgba(240, 39, 63, 0.07)';
    ctx.lineWidth = 1;
    const gridSize = 32;
    for (let x = 0; x < canvas.width; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(canvas.width, y_axis(x));
      ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    function y_axis(_x: number) {
      return canvas.height;
    }

    // 2. Top Header Bar
    ctx.fillStyle = '#0f1118';
    ctx.fillRect(0, 0, canvas.width, 42);
    ctx.strokeStyle = 'rgba(240, 39, 63, 0.4)';
    ctx.beginPath();
    ctx.moveTo(0, 42);
    ctx.lineTo(canvas.width, 42);
    ctx.stroke();

    // Pulse dot
    const pulseAlpha = 0.5 + Math.sin(elapsedTime * 4.0) * 0.4;
    ctx.fillStyle = `rgba(240, 39, 63, ${pulseAlpha})`;
    ctx.beginPath();
    ctx.arc(22, 21, 6, 0, Math.PI * 2);
    ctx.fill();

    ctx.font = 'bold 14px "JetBrains Mono", monospace';
    ctx.fillStyle = '#f5f5f7';
    ctx.fillText('VANTA // NEURO-SYMBOLIC SECURITY PIPELINE', 38, 26);

    ctx.fillStyle = '#f0273f';
    ctx.font = '12px "JetBrains Mono", monospace';
    ctx.fillText('CORE: ARMED [GNN + Z3]', 680, 26);

    ctx.fillStyle = '#9499a8';
    ctx.fillText(`UPTIME: ${(elapsedTime + 41.2).toFixed(1)}s`, 880, 26);

    // 3. Left Panel: Live Disassembly & Proof Stream
    codeScroll = (codeScroll + 1.2) % 40;
    ctx.font = '13px "JetBrains Mono", monospace';
    for (let i = 0; i < 15; i++) {
      const y = 72 + i * 36 - codeScroll;
      if (y < 46 || y > canvas.height - 10) continue;
      const snippet = codeSnippets[(i + Math.floor(elapsedTime * 1.2)) % codeSnippets.length];

      const isCritical = snippet.includes('CRITICAL') || snippet.includes('SAT') || snippet.includes('BREACH');
      if (isCritical) {
        ctx.fillStyle = 'rgba(240, 39, 63, 0.95)';
      } else {
        ctx.fillStyle = 'rgba(210, 215, 230, 0.75)';
      }
      ctx.fillText(`0x${(0x100000400 + i * 0x30).toString(16)}  ${snippet}`, 24, y);
    }

    // 4. Right Panel: Dynamic Neural Graph & Topology Radar
    const centerX = 820;
    const centerY = 240;
    const radius = 110;

    // Outer radar circles
    ctx.strokeStyle = 'rgba(240, 39, 63, 0.25)';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.stroke();

    ctx.strokeStyle = 'rgba(240, 39, 63, 0.4)';
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius * 0.65, 0, Math.PI * 2);
    ctx.stroke();

    // Radar rotating sweep arm
    const sweepAngle = elapsedTime * 2.2;
    ctx.strokeStyle = 'rgba(240, 39, 63, 0.8)';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(
      centerX + Math.cos(sweepAngle) * radius,
      centerY + Math.sin(sweepAngle) * radius
    );
    ctx.stroke();

    // Neural graph nodes
    const nodeCount = 8;
    for (let n = 0; n < nodeCount; n++) {
      const angle = (n / nodeCount) * Math.PI * 2 + elapsedTime * 0.2;
      const dist = radius * (0.35 + 0.5 * Math.sin(n * 2.1 + elapsedTime));
      const nx = centerX + Math.cos(angle) * dist;
      const ny = centerY + Math.sin(angle) * dist;

      ctx.fillStyle = n % 2 === 0 ? '#f0273f' : '#38bdf8';
      ctx.beginPath();
      ctx.arc(nx, ny, 3.5, 0, Math.PI * 2);
      ctx.fill();

      // Connector line to center
      ctx.strokeStyle = 'rgba(240, 39, 63, 0.2)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(nx, ny);
      ctx.stroke();
    }

    // Waveform strip at bottom
    ctx.strokeStyle = '#f0273f';
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let wx = 650; wx < 980; wx += 4) {
      const wy = 480 + Math.sin((wx * 0.05) + elapsedTime * 6) * 18 * Math.cos(elapsedTime * 2);
      if (wx === 650) ctx.moveTo(wx, wy);
      else ctx.lineTo(wx, wy);
    }
    ctx.stroke();

    ctx.fillStyle = '#7a7f8e';
    ctx.font = '11px "JetBrains Mono", monospace';
    ctx.fillText('Z3 CONSTRAINT WAVEFORM · 128-BIT ARITHMETIC', 650, 520);

    // 5. Sweeping horizontal laser scanline
    scanlineY = (scanlineY + 3.2) % canvas.height;
    ctx.fillStyle = 'rgba(240, 39, 63, 0.9)';
    ctx.fillRect(0, scanlineY, canvas.width, 2.5);

    const scanGrad = ctx.createLinearGradient(0, scanlineY - 20, 0, scanlineY + 20);
    scanGrad.addColorStop(0, 'rgba(240, 39, 63, 0)');
    scanGrad.addColorStop(0.5, 'rgba(240, 39, 63, 0.35)');
    scanGrad.addColorStop(1, 'rgba(240, 39, 63, 0)');
    ctx.fillStyle = scanGrad;
    ctx.fillRect(0, scanlineY - 20, canvas.width, 40);

    texture.needsUpdate = true;
  };

  return { canvas, ctx, texture, update };
}

/**
 * Creates the Monumental Floating 3D Laptop with custom PBR materials,
 * floating physics, surrounding ribbons and geometry, and screen radiance.
 */
export function createLaptopModel(
  scene: THREE.Scene,
  onLoadedCallback?: () => void
): LaptopController {
  const rootGroup = new THREE.Group();
  scene.add(rootGroup);

  // Dedicated Group for model and its components
  const laptopRig = new THREE.Group();
  rootGroup.add(laptopRig);

  // Floating components references
  let gemNode: THREE.Object3D | null = null;
  let sphere1Node: THREE.Object3D | null = null;
  let sphere2Node: THREE.Object3D | null = null;
  let coneNode: THREE.Object3D | null = null;
  let planeNode: THREE.Object3D | null = null;
  let lidNode: THREE.Object3D | null = null;

  const baseGemPos = new THREE.Vector3();
  const baseSphere1Pos = new THREE.Vector3();
  const baseSphere2Pos = new THREE.Vector3();
  const baseConePos = new THREE.Vector3();

  // Create High-Tech Screen Canvas Texture
  const screenCanvasObj = createLaptopScreenCanvas();

  // Lights for the Laptop Scene
  // Key Light (Clean White Studio Spotlight)
  const keyLight = new THREE.DirectionalLight(0xffffff, 2.4);
  keyLight.position.set(-2.0, 3.5, 5.0);
  rootGroup.add(keyLight);

  // Crimson Rim Light (Rear Right) - matches the site's primary crimson
  const rimRight = new THREE.DirectionalLight(0xf0273f, 5.8);
  rimRight.position.set(4.5, 2.8, -2.5);
  rootGroup.add(rimRight);

  // Crimson Rim Light (Rear Left)
  const rimLeft = new THREE.DirectionalLight(0xf0273f, 4.2);
  rimLeft.position.set(-4.5, 2.0, -2.5);
  rootGroup.add(rimLeft);

  // Screen Radiance Point Light (Casts glowing red/white onto keyboard & chassis)
  const redPointLight = new THREE.PointLight(0xff354b, 3.5, 5.5);
  redPointLight.position.set(0, 0.4, 0.8);
  laptopRig.add(redPointLight);

  // Soft Ambient Fill Light
  const ambientFill = new THREE.AmbientLight(0x181a24, 1.4);
  rootGroup.add(ambientFill);

  // Contact Shadow Plane beneath the floating model
  const shadowCanvas = document.createElement('canvas');
  shadowCanvas.width = 256;
  shadowCanvas.height = 256;
  const sCtx = shadowCanvas.getContext('2d');
  if (sCtx) {
    const rad = sCtx.createRadialGradient(128, 128, 10, 128, 128, 120);
    rad.addColorStop(0, 'rgba(0, 0, 0, 0.7)');
    rad.addColorStop(0.4, 'rgba(240, 39, 63, 0.15)');
    rad.addColorStop(1, 'rgba(0, 0, 0, 0)');
    sCtx.fillStyle = rad;
    sCtx.fillRect(0, 0, 256, 256);
  }
  const shadowTex = new THREE.CanvasTexture(shadowCanvas);
  const shadowGeo = new THREE.PlaneGeometry(5.5, 4.0);
  const shadowMat = new THREE.MeshBasicMaterial({
    map: shadowTex,
    transparent: true,
    opacity: 0.65,
    depthWrite: false,
  });
  const contactShadow = new THREE.Mesh(shadowGeo, shadowMat);
  contactShadow.rotation.x = -Math.PI / 2;
  contactShadow.position.set(0, -1.8, 0);
  rootGroup.add(contactShadow);

  // Bespoke Materials System matching VANTA's Obsidian & Crimson Aesthetic
  // 1. Laptop Chassis (Space Obsidian Titanium)
  const chassisMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0x181920),
    roughness: 0.32,
    metalness: 0.85,
    transparent: true,
    opacity: 1.0,
  });

  // 2. Keyboard Well / Plate
  const keyPlateMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0x111218),
    roughness: 0.42,
    metalness: 0.50,
    transparent: true,
    opacity: 1.0,
  });

  // 3. Tactile Keys (Deep Matte Charcoal with Crimson Backlight Resonance)
  const keycapMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0x14151c),
    emissive: new THREE.Color(0x28050a),
    emissiveIntensity: 0.65,
    roughness: 0.52,
    metalness: 0.20,
    transparent: true,
    opacity: 1.0,
  });

  // 4. Trackpad (Silky Frosted Dark Glass)
  const trackpadMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0x20222d),
    roughness: 0.22,
    metalness: 0.38,
    transparent: true,
    opacity: 1.0,
  });

  // 5. Flowing Satin Silk Ribbons (Plane & Blank)
  // Iridescent titanium charcoal satin that catches crimson rim reflections brilliantly!
  const ribbonMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0x262834),
    emissive: new THREE.Color(0x2b060d),
    emissiveIntensity: 0.75,
    roughness: 0.26,
    metalness: 0.48,
    side: THREE.DoubleSide,
    transparent: true,
    opacity: 1.0,
  });

  // 6. Floating Gem Torus Ring (Mirror Polished Titanium Chrome with Ruby reflections)
  const gemTorusMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0xebedf8),
    roughness: 0.08,
    metalness: 0.98,
    transparent: true,
    opacity: 1.0,
  });

  // 7. Floating Ruby Sphere (Vibrant Crimson Core Orb)
  const sphereRubyMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0xf0273f),
    emissive: new THREE.Color(0x600612),
    emissiveIntensity: 0.7,
    roughness: 0.16,
    metalness: 0.65,
    transparent: true,
    opacity: 1.0,
  });

  // 8. Floating Platinum Sphere (Mirror Chrome)
  const sphereChromeMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0xf5f6fb),
    roughness: 0.06,
    metalness: 0.98,
    transparent: true,
    opacity: 1.0,
  });

  // 9. Floating Cone (Stealth Obsidian)
  const coneMat = new THREE.MeshStandardMaterial({
    color: new THREE.Color(0x191a24),
    roughness: 0.22,
    metalness: 0.85,
    transparent: true,
    opacity: 1.0,
  });

  // 10. Screen Display Material (Luminous High-Tech Screen)
  const screenMat = new THREE.MeshStandardMaterial({
    map: screenCanvasObj?.texture || null,
    emissiveMap: screenCanvasObj?.texture || null,
    emissive: new THREE.Color(0xffffff),
    emissiveIntensity: 0.92,
    roughness: 0.12,
    metalness: 0.08,
    transparent: true,
    opacity: 1.0,
  });

  let isLoaded = false;

  // Load the GLTF Laptop Model
  const loader = new GLTFLoader();
  loader.load(
    '/glb/laptop.glb',
    (gltf) => {
      const model = gltf.scene;

      // Extract specific node handles for tailored materials and floating physics
      model.traverse((child) => {
        const name = child.name || '';
        const parentName = child.parent?.name || '';
        const grandParentName = child.parent?.parent?.name || '';

        if (name === 'Gem') gemNode = child;
        if (name === 'Sphere1') sphere1Node = child;
        if (name === 'Sphere2') sphere2Node = child;
        if (name === 'Cone') coneNode = child;
        if (name === 'Plane') planeNode = child;
        if (name === 'Lid') lidNode = child;

        if ((child as THREE.Mesh).isMesh) {
          const mesh = child as THREE.Mesh;
          mesh.castShadow = true;
          mesh.receiveShadow = true;

          // Assign materials intelligently based on node hierarchy
          const hierarchy = `${grandParentName}/${parentName}/${name}`.toLowerCase();

          if (hierarchy.includes('keys')) {
            mesh.material = keycapMat;
          } else if (hierarchy.includes('trackpad')) {
            mesh.material = trackpadMat;
          } else if (hierarchy.includes('key_plate')) {
            mesh.material = keyPlateMat;
          } else if (hierarchy.includes('plane') || hierarchy.includes('blank')) {
            mesh.material = ribbonMat;
          } else if (hierarchy.includes('gem')) {
            mesh.material = gemTorusMat;
          } else if (hierarchy.includes('sphere1')) {
            mesh.material = sphereRubyMat;
          } else if (hierarchy.includes('sphere2')) {
            mesh.material = sphereChromeMat;
          } else if (hierarchy.includes('cone')) {
            mesh.material = coneMat;
          } else if (name === 'Object_17' || hierarchy.includes('cube')) {
            // Native GLB Screen bezel / inlay
            mesh.material = screenMat;
          } else {
            // Main chassis, lid cover, hinges, body
            mesh.material = chassisMat;
          }
        }
      });

      // Add a dedicated ultra-crisp 16:10 illuminated cyber screen into Lid
      // to ensure flawless, razor-sharp HUD projection directly facing the camera
      if (lidNode) {
        const screenGeo = new THREE.PlaneGeometry(32.8, 20.8);
        const dedicatedScreenMesh = new THREE.Mesh(screenGeo, screenMat);
        // Positioned flush on the inner display surface of the laptop lid
        dedicatedScreenMesh.position.set(0, 1.45, 12.8);
        dedicatedScreenMesh.rotation.x = -Math.PI / 2 + 0.17;
        lidNode.add(dedicatedScreenMesh);
      }

      // Record base positions for harmonic floating animations
      if (gemNode) baseGemPos.copy(gemNode.position);
      if (sphere1Node) baseSphere1Pos.copy(sphere1Node.position);
      if (sphere2Node) baseSphere2Pos.copy(sphere2Node.position);
      if (coneNode) baseConePos.copy(coneNode.position);

      // Wrapper group for centering and scaling
      const centerWrapper = new THREE.Group();
      centerWrapper.name = 'LaptopCenterWrapper';
      centerWrapper.add(model);

      // Compute bounding box of unscaled model
      const box = new THREE.Box3().setFromObject(model);
      const center = box.getCenter(new THREE.Vector3());
      const size = box.getSize(new THREE.Vector3());

      // Center model inside centerWrapper strictly around (0, 0, 0)
      model.position.set(-center.x, -center.y, -center.z);

      // Scale centerWrapper uniformly around (0, 0, 0)
      const maxDim = Math.max(size.x, size.y, size.z);
      const targetScale = 4.2 / maxDim;
      centerWrapper.scale.setScalar(targetScale);

      // Default viewing orientation matching reference:
      // Front view, slightly pitched forward to showcase keyboard, screen, and flowing ribbons
      centerWrapper.rotation.set(0.14, -0.05, 0.0);

      laptopRig.add(centerWrapper);
      isLoaded = true;

      if (onLoadedCallback) {
        onLoadedCallback();
      }
    },
    undefined,
    (err) => {
      console.warn('Failed to load /glb/laptop.glb, attempting fallback to /models/laptop.glb', err);
      loader.load('/models/laptop.glb', (gltf) => {
        laptopRig.add(gltf.scene);
        isLoaded = true;
        if (onLoadedCallback) onLoadedCallback();
      });
    }
  );

  // Animation Update Function
  const update = (
    elapsedTime: number,
    progress: number,
    mouseX: number,
    mouseY: number,
    isDarkTheme: boolean = true
  ) => {
    // 1. Update live screen canvas texture
    if (screenCanvasObj) {
      screenCanvasObj.update(elapsedTime);
    }

    if (!isLoaded) return;

    // 2. Harmonic Floating & Breathing Animation for the entire Laptop Rig
    // Bobbing up and down gently
    const floatY = Math.sin(elapsedTime * 1.5) * 0.07;
    laptopRig.position.y = floatY;

    // Gentle 3D floating pitch, yaw, and roll with smooth mouse parallax
    const targetPitch = 0.08 + Math.cos(elapsedTime * 1.0) * 0.025 - mouseY * 0.16;
    const targetYaw = -0.04 + Math.sin(elapsedTime * 0.8) * 0.035 + mouseX * 0.28;
    const targetRoll = Math.sin(elapsedTime * 0.6) * 0.012;

    laptopRig.rotation.x = targetPitch;
    laptopRig.rotation.y = targetYaw;
    laptopRig.rotation.z = targetRoll;

    // 3. Individual Floating Motion for Surrounding Geometric Shapes
    if (gemNode) {
      gemNode.rotation.z += 0.012;
      gemNode.position.y = baseGemPos.y + Math.sin(elapsedTime * 2.2) * 0.05;
    }
    if (sphere1Node) {
      sphere1Node.position.y = baseSphere1Pos.y + Math.sin(elapsedTime * 1.8 + 1.0) * 0.045;
      sphere1Node.position.x = baseSphere1Pos.x + Math.cos(elapsedTime * 1.4) * 0.03;
    }
    if (sphere2Node) {
      sphere2Node.position.y = baseSphere2Pos.y + Math.cos(elapsedTime * 2.0 + 0.4) * 0.04;
    }
    if (coneNode) {
      coneNode.rotation.y += 0.01;
      coneNode.position.y = baseConePos.y + Math.sin(elapsedTime * 1.6) * 0.03;
    }
    if (planeNode) {
      planeNode.rotation.z = Math.sin(elapsedTime * 0.7) * 0.015;
    }

    // 4. Contact shadow breathing
    contactShadow.scale.setScalar(1.0 + Math.sin(elapsedTime * 1.5) * 0.05);
    contactShadow.material.opacity = 0.55 - floatY * 0.8;

    // 5. Scroll Transition Choreography (0.00 <= progress <= 0.46)
    // As progress increases towards 0.40, the camera pushes into the laptop screen,
    // the laptop scales up and fades out (pops out), revealing the dark void beneath!
    if (progress < 0.40) {
      rootGroup.visible = true;
      const t = progress / 0.40; // 0 -> 1

      // Smooth zoom and scale pop-out
      const scaleVal = 1.0 + t * 0.45;
      rootGroup.scale.set(scaleVal, scaleVal, scaleVal);
      rootGroup.position.z = t * 1.8;

      // Materials fade smoothly as we push through into the void
      const opacity = Math.max(0, 1.0 - t * 1.5);
      chassisMat.opacity = opacity;
      ribbonMat.opacity = opacity;
      keycapMat.opacity = opacity;
      contactShadow.material.opacity = (0.55 - floatY * 0.8) * opacity;
    } else {
      rootGroup.visible = false;
    }

    // 6. Lighting adaptation to theme
    if (!isDarkTheme) {
      ambientFill.intensity = 2.0;
      keyLight.intensity = 2.8;
      rimRight.intensity = 3.5;
    } else {
      ambientFill.intensity = 1.3;
      keyLight.intensity = 2.4;
      rimRight.intensity = 5.8;
    }
  };

  // Disposal handler
  const dispose = () => {
    scene.remove(rootGroup);
    chassisMat.dispose();
    keyPlateMat.dispose();
    keycapMat.dispose();
    trackpadMat.dispose();
    ribbonMat.dispose();
    gemTorusMat.dispose();
    sphereRubyMat.dispose();
    sphereChromeMat.dispose();
    coneMat.dispose();
    screenMat.dispose();
    shadowMat.dispose();
    shadowGeo.dispose();
    shadowTex.dispose();
    if (screenCanvasObj?.texture) {
      screenCanvasObj.texture.dispose();
    }
  };

  return {
    group: rootGroup,
    update,
    dispose,
    isLoaded,
    screenTexture: screenCanvasObj?.texture || null,
    redPointLight,
    keyLight,
    rimRight,
    rimLeft,
  };
}

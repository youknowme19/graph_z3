import * as THREE from 'three';

/**
 * HeroSculpture3D
 * Monumental Architectural 3D Sculpture for the VANTA White Hero.
 * 
 * Creative Direction:
 * - High-end industrial design + contemporary museum sculpture + futuristic architecture.
 * - Materials: Polished porcelain white, brushed titanium/silver spine, translucent frosted glass blade,
 *   graphite shadow-line inlays, and an articulating precision crimson core.
 * - Framing:
 *   Phase A: Asymmetrical architectural arch that frames the hero headline with magnificent negative space,
 *     ensuring 100% readability.
 *   Phase B: As text fades, sculpture glides into center-stage; camera pushes in, specular highlights glint.
 *   Phase C: Signature blooming transformation: satellite wings decouple, crimson core extends into the focal center.
 *   Phase D: Crimson light surges, casting radiant red reflections on porcelain as background shifts to dark.
 *   Phase E: Camera glides through the sculpture's central opening into the dark void -> hacker emerges.
 */

export interface SculptureController {
  group: THREE.Group;
  update: (elapsedTime: number, scrollProgress: number, mouseX: number, mouseY: number, isDarkTheme?: boolean) => void;
  dispose: () => void;
  redPointLight: THREE.PointLight;
  studioKeyLight: THREE.DirectionalLight;
  studioFillLight: THREE.DirectionalLight;
  contactShadow: THREE.Mesh;
}

/**
 * Compute Rotation Minimizing Frames (RMF) along a 3D curve to prevent twisting artifacts
 */
function computeRMF(curve: THREE.CatmullRomCurve3, divisions: number) {
  const points: THREE.Vector3[] = [];
  const tangents: THREE.Vector3[] = [];
  const normals: THREE.Vector3[] = [];
  const binormals: THREE.Vector3[] = [];

  for (let i = 0; i <= divisions; i++) {
    const u = i / divisions;
    points.push(curve.getPointAt(u));
    tangents.push(curve.getTangentAt(u).normalize());
  }

  let initialNormal = new THREE.Vector3(0, 1, 0);
  if (Math.abs(tangents[0].dot(initialNormal)) > 0.9) {
    initialNormal.set(1, 0, 0);
  }
  const firstBinormal = new THREE.Vector3().crossVectors(tangents[0], initialNormal).normalize();
  const firstNormal = new THREE.Vector3().crossVectors(firstBinormal, tangents[0]).normalize();

  normals.push(firstNormal);
  binormals.push(firstBinormal);

  for (let i = 0; i < divisions; i++) {
    const p0 = points[i];
    const p1 = points[i + 1];
    const t0 = tangents[i];
    const t1 = tangents[i + 1];

    const v1 = new THREE.Vector3().subVectors(p1, p0);
    const c1 = v1.dot(v1);

    const rL = normals[i].clone().sub(v1.clone().multiplyScalar((2 / c1) * v1.dot(normals[i])));
    const tL = t0.clone().sub(v1.clone().multiplyScalar((2 / c1) * v1.dot(t0)));

    const v2 = new THREE.Vector3().subVectors(t1, tL);
    const c2 = v2.dot(v2);

    let nextNormal: THREE.Vector3;
    if (c2 > 1e-6) {
      nextNormal = rL.clone().sub(v2.clone().multiplyScalar((2 / c2) * v2.dot(rL))).normalize();
    } else {
      nextNormal = rL.normalize();
    }

    const nextBinormal = new THREE.Vector3().crossVectors(t1, nextNormal).normalize();
    normals.push(nextNormal);
    binormals.push(nextBinormal);
  }

  return { points, tangents, normals, binormals };
}

/**
 * Generate smooth architectural ribbon geometry with precision bevelled cross-section
 */
function createPorcelainRibbonGeometry(
  curve: THREE.CatmullRomCurve3,
  divisions: number,
  widthFn: (u: number) => number,
  thickFn: (u: number) => number
): THREE.BufferGeometry {
  const { points, normals, binormals } = computeRMF(curve, divisions);
  const geom = new THREE.BufferGeometry();

  const crossSections = 20;
  const vertices: number[] = [];
  const uvs: number[] = [];
  const indices: number[] = [];

  for (let i = 0; i <= divisions; i++) {
    const u = i / divisions;
    const p = points[i];
    const n = normals[i];
    const b = binormals[i];

    const w = widthFn(u);
    const t = thickFn(u);

    for (let j = 0; j <= crossSections; j++) {
      const v = j / crossSections;
      const angle = v * Math.PI * 2;
      const cosA = Math.cos(angle);
      const sinA = Math.sin(angle);

      const edgeFactor = 1.0 - 0.12 * Math.pow(Math.abs(cosA), 4);
      const xOffset = cosA * (w * 0.5);
      const yOffset = sinA * (t * 0.5) * edgeFactor;

      const vertex = p.clone()
        .add(b.clone().multiplyScalar(xOffset))
        .add(n.clone().multiplyScalar(yOffset));

      vertices.push(vertex.x, vertex.y, vertex.z);
      uvs.push(u, v);
    }
  }

  const stride = crossSections + 1;
  for (let i = 0; i < divisions; i++) {
    for (let j = 0; j < crossSections; j++) {
      const a = i * stride + j;
      const b = (i + 1) * stride + j;
      const c = (i + 1) * stride + (j + 1);
      const d = i * stride + (j + 1);

      indices.push(a, b, d);
      indices.push(b, c, d);
    }
  }

  geom.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
  geom.setAttribute('uv', new THREE.Float32BufferAttribute(uvs, 2));
  geom.setIndex(indices);
  geom.computeVertexNormals();

  return geom;
}

/**
 * Generate precision aerodynamic blade geometry for wings and glass fins
 */
function createAerodynamicBladeGeometry(
  length: number,
  maxWidth: number,
  maxThickness: number,
  curvature: number
): THREE.BufferGeometry {
  const geom = new THREE.BufferGeometry();
  const segmentsU = 48;
  const segmentsV = 16;

  const vertices: number[] = [];
  const uvs: number[] = [];
  const indices: number[] = [];

  for (let i = 0; i <= segmentsU; i++) {
    const u = i / segmentsU;
    const width = Math.sin(u * Math.PI) * maxWidth;
    const thickness = Math.sin(u * Math.PI) * maxThickness * (1.0 - u * 0.35);
    const zCurve = Math.pow(u, 1.5) * curvature;
    const yPos = (u - 0.5) * length;

    for (let j = 0; j <= segmentsV; j++) {
      const v = j / segmentsV;
      const angle = v * Math.PI * 2;
      const cosA = Math.cos(angle);
      const sinA = Math.sin(angle);

      const x = cosA * (width * 0.5);
      const z = zCurve + sinA * (thickness * 0.5) * (0.85 + 0.15 * cosA);

      vertices.push(x, yPos, z);
      uvs.push(u, v);
    }
  }

  const stride = segmentsV + 1;
  for (let i = 0; i < segmentsU; i++) {
    for (let j = 0; j < segmentsV; j++) {
      const a = i * stride + j;
      const b = (i + 1) * stride + j;
      const c = (i + 1) * stride + (j + 1);
      const d = i * stride + (j + 1);

      indices.push(a, b, d);
      indices.push(b, c, d);
    }
  }

  geom.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
  geom.setAttribute('uv', new THREE.Float32BufferAttribute(uvs, 2));
  geom.setIndex(indices);
  geom.computeVertexNormals();

  return geom;
}

/**
 * Radial Contact Shadow Texture Generator
 */
function createContactShadowTexture(): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 512;
  canvas.height = 512;
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.clearRect(0, 0, 512, 512);
    const grad = ctx.createRadialGradient(256, 256, 20, 256, 256, 240);
    grad.addColorStop(0, 'rgba(15, 20, 30, 0.32)');
    grad.addColorStop(0.3, 'rgba(15, 20, 30, 0.16)');
    grad.addColorStop(0.65, 'rgba(15, 20, 30, 0.05)');
    grad.addColorStop(1, 'rgba(15, 20, 30, 0.0)');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.ellipse(256, 256, 230, 160, 0, 0, Math.PI * 2);
    ctx.fill();
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  return texture;
}

/**
 * Main Sculpture Factory
 */
export function createHeroSculpture(scene: THREE.Scene): SculptureController {
  const rootGroup = new THREE.Group();
  rootGroup.name = 'HeroSculptureRoot';
  scene.add(rootGroup);

  // =========================================================================
  // Materials
  // =========================================================================

  // 1. Polished Porcelain White (Core Sculpture Material)
  const porcelainMat = new THREE.MeshPhysicalMaterial({
    color: 0xfbfcfe,
    roughness: 0.14,
    metalness: 0.03,
    clearcoat: 1.0,
    clearcoatRoughness: 0.08,
    reflectivity: 0.95,
    sheen: 0.45,
    sheenColor: 0xffffff,
  });

  // 2. Brushed Pale Titanium / Silver (Precision Spines and Edge Accents)
  const titaniumMat = new THREE.MeshStandardMaterial({
    color: 0xdde4ec,
    roughness: 0.20,
    metalness: 0.92,
  });

  // 3. Translucent Frosted Glass (Interlocking Aerodynamic Canopy)
  const frostedGlassMat = new THREE.MeshPhysicalMaterial({
    color: 0xf5f8fc,
    transmission: 0.88,
    opacity: 0.92,
    transparent: true,
    roughness: 0.16,
    ior: 1.48,
    thickness: 1.1,
    specularIntensity: 1.0,
    clearcoat: 0.85,
    clearcoatRoughness: 0.08,
  });

  // 4. Deep Graphite Inlay (Recessed Shadow Channels)
  const graphiteMat = new THREE.MeshStandardMaterial({
    color: 0x1b1d24,
    roughness: 0.35,
    metalness: 0.70,
  });

  // 5. Precision Crimson Core (Inner Razor Blade)
  const crimsonCoreMat = new THREE.MeshPhysicalMaterial({
    color: 0xf0273f,
    emissive: 0xaa081a,
    emissiveIntensity: 0.75,
    roughness: 0.14,
    metalness: 0.55,
    clearcoat: 1.0,
    clearcoatRoughness: 0.04,
  });

  // =========================================================================
  // Geometry 1: The Monumental Architectural Ribbon
  // Intentionally frames the hero headline with majestic negative space,
  // respecting the top navigation bar height and never cutting through text.
  // =========================================================================
  const mainSplinePoints = [
    new THREE.Vector3(2.8, 1.25, -0.3),   // 0: upper right anchor
    new THREE.Vector3(3.4, 0.20, 0.15),   // 1: far right perimeter wing
    new THREE.Vector3(2.9, -1.05, 0.45),  // 2: sweeping down the right edge
    new THREE.Vector3(1.8, -1.95, 0.35),  // 3: bottom-right curve
    new THREE.Vector3(0.0, -2.15, -0.1),  // 4: curving underneath the subtitle & scroll indicator
    new THREE.Vector3(-1.6, -1.95, -0.35), // 5: bottom-left curve
    new THREE.Vector3(-2.8, -1.05, -0.55), // 6: ascending left base
    new THREE.Vector3(-3.4, 0.20, -0.2),  // 7: far left outer wing
    new THREE.Vector3(-2.8, 1.25, 0.1),   // 8: upper left soaring shoulder
    new THREE.Vector3(-1.6, 1.62, 0.25),  // 9: top left canopy arching cleanly above headline
    new THREE.Vector3(0.0, 1.68, 0.15),   // 10: top center canopy crossing comfortably above headline, safely below navbar
    new THREE.Vector3(1.6, 1.62, -0.1),   // 11: top right canopy descent
  ];
  const mainSpline = new THREE.CatmullRomCurve3(mainSplinePoints, true);

  const widthFn = (u: number) => {
    return 0.44 + 0.24 * Math.sin(u * Math.PI * 2) * Math.sin(u * Math.PI * 2) + 0.12 * Math.cos(u * Math.PI * 4);
  };
  const thickFn = (u: number) => {
    return 0.15 + 0.05 * Math.cos(u * Math.PI * 2);
  };

  const ribbonGeo = createPorcelainRibbonGeometry(mainSpline, 160, widthFn, thickFn);
  const ribbonMesh = new THREE.Mesh(ribbonGeo, porcelainMat);
  ribbonMesh.castShadow = true;
  ribbonMesh.receiveShadow = true;

  const mainRibbonGroup = new THREE.Group();
  mainRibbonGroup.name = 'MainRibbonGroup';
  mainRibbonGroup.add(ribbonMesh);
  rootGroup.add(mainRibbonGroup);

  // Geometry 2: The Precision Titanium Spine
  const spineGeo = new THREE.TubeGeometry(mainSpline, 160, 0.024, 8, true);
  const spineMesh = new THREE.Mesh(spineGeo, titaniumMat);
  spineMesh.scale.set(1.018, 1.018, 1.018);
  mainRibbonGroup.add(spineMesh);

  // Slender graphite shadow-line inlay
  const inlayGeo = new THREE.TubeGeometry(mainSpline, 160, 0.015, 6, true);
  const inlayMesh = new THREE.Mesh(inlayGeo, graphiteMat);
  inlayMesh.scale.set(0.985, 0.985, 0.985);
  mainRibbonGroup.add(inlayMesh);

  // Geometry 3: Translucent Frosted Glass Interlocking Blade (Upper Right Perimeter)
  const glassBladeGroup = new THREE.Group();
  glassBladeGroup.name = 'GlassBladeGroup';
  const glassBladeGeo = createAerodynamicBladeGeometry(3.2, 0.65, 0.14, -0.4);
  const glassBladeMesh = new THREE.Mesh(glassBladeGeo, frostedGlassMat);
  glassBladeMesh.rotation.set(0.2, 0.45, -0.45);
  glassBladeMesh.position.set(2.55, 0.85, 0.15);
  glassBladeGroup.add(glassBladeMesh);
  rootGroup.add(glassBladeGroup);

  // Geometry 4: Articulating Crimson Core Blade (Tucked on Lower Right Perimeter in Phase A)
  const crimsonCoreGroup = new THREE.Group();
  crimsonCoreGroup.name = 'CrimsonCoreGroup';
  const crimsonBladeGeo = createAerodynamicBladeGeometry(2.5, 0.40, 0.12, 0.28);
  const crimsonCoreMesh = new THREE.Mesh(crimsonBladeGeo, crimsonCoreMat);
  crimsonCoreMesh.rotation.set(-0.15, 0.35, -0.45);
  crimsonCoreGroup.add(crimsonCoreMesh);
  crimsonCoreGroup.position.set(2.50, -0.65, 0.25);
  rootGroup.add(crimsonCoreGroup);

  // Internal Crimson Light
  const redPointLight = new THREE.PointLight(0xf0273f, 1.6, 7);
  redPointLight.position.set(2.45, -0.55, 0.35);
  rootGroup.add(redPointLight);

  // Geometry 5 & 6: Articulating Satellite Wings (Left and Right Framing)
  const wingLeftGroup = new THREE.Group();
  wingLeftGroup.name = 'WingLeftGroup';
  const wingLeftGeo = createAerodynamicBladeGeometry(2.7, 0.52, 0.12, 0.38);
  const wingLeftMesh = new THREE.Mesh(wingLeftGeo, porcelainMat);
  const wingLeftEdge = new THREE.Mesh(wingLeftGeo.clone(), titaniumMat);
  wingLeftEdge.scale.set(0.97, 0.97, 0.97);
  wingLeftMesh.add(wingLeftEdge);
  wingLeftGroup.add(wingLeftMesh);
  wingLeftGroup.position.set(-2.9, 0.55, -0.2);
  wingLeftGroup.rotation.set(0.35, -0.25, 0.4);
  rootGroup.add(wingLeftGroup);

  const wingRightGroup = new THREE.Group();
  wingRightGroup.name = 'WingRightGroup';
  const wingRightGeo = createAerodynamicBladeGeometry(3.0, 0.60, 0.14, -0.28);
  const wingRightMesh = new THREE.Mesh(wingRightGeo, porcelainMat);
  const wingRightEdge = new THREE.Mesh(wingRightGeo.clone(), titaniumMat);
  wingRightEdge.scale.set(0.97, 0.97, 0.97);
  wingRightMesh.add(wingRightEdge);
  wingRightGroup.add(wingRightMesh);
  wingRightGroup.position.set(2.95, 0.65, 0.0);
  wingRightGroup.rotation.set(-0.15, 0.35, -0.35);
  rootGroup.add(wingRightGroup);

  // Studio Lighting & Contact Shadow Catcher
  const studioKeyLight = new THREE.DirectionalLight(0xffffff, 2.0);
  studioKeyLight.position.set(-5.0, 8.0, 6.0);
  scene.add(studioKeyLight);

  const studioFillLight = new THREE.DirectionalLight(0xecf0f8, 1.1);
  studioFillLight.position.set(6.0, -3.0, 4.0);
  scene.add(studioFillLight);

  const contactShadowTexture = createContactShadowTexture();
  const shadowGeo = new THREE.PlaneGeometry(8, 5.5);
  const shadowMat = new THREE.MeshBasicMaterial({
    map: contactShadowTexture,
    transparent: true,
    opacity: 0.30,
    depthWrite: false,
  });
  const contactShadow = new THREE.Mesh(shadowGeo, shadowMat);
  contactShadow.rotation.x = -Math.PI / 2;
  contactShadow.position.set(0.3, -2.15, 0);
  scene.add(contactShadow);

  // Initial sculpture placement: centered, comfortably below top navigation
  rootGroup.position.set(0.0, -0.06, 0.0);
  rootGroup.scale.setScalar(1.03);

  /**
   * Main Animation & Scroll Update Loop
   * Synchronized with active light/dark theme.
   */
  const update = (
    elapsedTime: number,
    p: number,
    mouseX: number,
    mouseY: number,
    isDarkTheme: boolean = false
  ) => {
    if (p > 0.48) {
      rootGroup.visible = false;
      contactShadow.visible = false;
      studioKeyLight.intensity = 0;
      studioFillLight.intensity = 0;
      redPointLight.intensity = 0;
      return;
    }

    rootGroup.visible = true;
    contactShadow.visible = true;

    // Theme lighting baseline adaptation
    const keyBase = isDarkTheme ? 2.5 : 2.0;
    const fillBase = isDarkTheme ? 1.35 : 1.1;
    const shadowBase = isDarkTheme ? 0.08 : 0.30;
    if (isDarkTheme) {
      studioFillLight.color.setHex(0x9cb4d8);
    } else {
      studioFillLight.color.setHex(0xecf0f8);
    }

    // Subtle idle breathing
    const idleRotY = Math.sin(elapsedTime * 0.4) * 0.025;
    const idleRotX = Math.cos(elapsedTime * 0.3) * 0.018;
    const idleBobY = Math.sin(elapsedTime * 0.5) * 0.02;

    // Phase A: The quiet reveal (0.00 <= p < 0.10)
    // Cleanly frames headline with generous negative space; red blade stays on perimeter
    if (p < 0.10) {
      const t = p / 0.10;
      rootGroup.position.set(
        0.0 + mouseX * 0.12,
        -0.06 + idleBobY + mouseY * 0.08,
        0.0 - t * 0.15
      );
      rootGroup.rotation.set(
        0.04 + idleRotX - mouseY * 0.05,
        -0.06 + idleRotY + mouseX * 0.06,
        0.01
      );
      rootGroup.scale.setScalar(1.03);

      wingLeftGroup.position.set(-2.9, 0.55, -0.2);
      wingLeftGroup.rotation.set(0.35, -0.25, 0.4);

      wingRightGroup.position.set(2.95, 0.65, 0.0);
      wingRightGroup.rotation.set(-0.15, 0.35, -0.35);

      crimsonCoreGroup.position.set(2.50, -0.65, 0.25);
      crimsonCoreGroup.rotation.set(-0.15, 0.35, -0.45);
      crimsonCoreGroup.scale.setScalar(1.0);

      redPointLight.position.set(2.45, -0.55, 0.35);
      redPointLight.intensity = 1.4 + Math.sin(elapsedTime * 2.0) * 0.3;
      studioKeyLight.intensity = keyBase;
      studioFillLight.intensity = fillBase;
      contactShadow.material.opacity = shadowBase;

      porcelainMat.opacity = 1.0;
      frostedGlassMat.opacity = 0.92;
      crimsonCoreMat.opacity = 1.0;
    }
    // Phase B: Enter the sculpture (0.10 <= p < 0.20)
    // Text begins fading out; sculpture tilts to reveal 3D volume & internal folds
    else if (p >= 0.10 && p < 0.20) {
      const t = (p - 0.10) / 0.10; // 0 -> 1

      rootGroup.position.x = THREE.MathUtils.lerp(0.0, -0.05, t) + mouseX * 0.12;
      rootGroup.position.y = THREE.MathUtils.lerp(-0.06, -0.03, t) + idleBobY + mouseY * 0.08;
      rootGroup.position.z = THREE.MathUtils.lerp(-0.15, 0.25, t);

      rootGroup.rotation.x = THREE.MathUtils.lerp(0.04, 0.20, t) + idleRotX - mouseY * 0.05;
      rootGroup.rotation.y = THREE.MathUtils.lerp(-0.06, 0.30, t) + idleRotY + mouseX * 0.06;
      rootGroup.rotation.z = THREE.MathUtils.lerp(0.01, -0.05, t);

      glassBladeGroup.rotation.y = t * 0.25;
      rootGroup.scale.setScalar(THREE.MathUtils.lerp(1.03, 1.08, t));

      // Crimson blade begins moving inward as text fades away
      crimsonCoreGroup.position.x = THREE.MathUtils.lerp(2.50, 1.6, t);
      crimsonCoreGroup.position.y = THREE.MathUtils.lerp(-0.65, -0.1, t);
      crimsonCoreGroup.position.z = THREE.MathUtils.lerp(0.25, 0.2, t);
      crimsonCoreGroup.rotation.y = THREE.MathUtils.lerp(0.35, -0.3, t);

      wingLeftGroup.position.x = THREE.MathUtils.lerp(-2.9, -2.0, t);
      wingLeftGroup.position.y = THREE.MathUtils.lerp(0.55, 0.8, t);
      wingRightGroup.position.x = THREE.MathUtils.lerp(2.95, 2.3, t);
      wingRightGroup.position.y = THREE.MathUtils.lerp(0.65, 1.3, t);

      redPointLight.position.set(
        crimsonCoreGroup.position.x,
        crimsonCoreGroup.position.y + 0.1,
        crimsonCoreGroup.position.z + 0.2
      );
      redPointLight.intensity = THREE.MathUtils.lerp(1.4, 2.8, t);
      studioKeyLight.intensity = THREE.MathUtils.lerp(keyBase, keyBase * 1.15, t);
      studioFillLight.intensity = THREE.MathUtils.lerp(fillBase, fillBase * 1.1, t);
      contactShadow.material.opacity = THREE.MathUtils.lerp(shadowBase, shadowBase * 1.05, t);

      porcelainMat.opacity = 1.0;
      frostedGlassMat.opacity = 0.92;
      crimsonCoreMat.opacity = 1.0;
    }
    // Phase C: The signature transformation (0.20 <= p < 0.32)
    // Headline is now gone; wings bloom outward, crimson core articulates into focal center!
    else if (p >= 0.20 && p < 0.32) {
      const t = (p - 0.20) / 0.12; // 0 -> 1

      rootGroup.position.x = THREE.MathUtils.lerp(-0.05, 0.0, t) + mouseX * 0.12;
      rootGroup.position.y = THREE.MathUtils.lerp(-0.03, -0.04, t) + mouseY * 0.08;
      rootGroup.position.z = THREE.MathUtils.lerp(0.25, 0.55, t);

      rootGroup.rotation.x = THREE.MathUtils.lerp(0.20, 0.32, t);
      rootGroup.rotation.y = THREE.MathUtils.lerp(0.30, 0.65, t);
      rootGroup.rotation.z = THREE.MathUtils.lerp(-0.05, -0.12, t);

      // Satellite wings decouple and sweep gracefully across depth
      wingLeftGroup.position.x = THREE.MathUtils.lerp(-2.0, -2.6, t);
      wingLeftGroup.position.y = THREE.MathUtils.lerp(0.8, 1.1, t);
      wingLeftGroup.position.z = THREE.MathUtils.lerp(-0.2, 0.5, t);
      wingLeftGroup.rotation.y = THREE.MathUtils.lerp(-0.3, -0.7, t);

      wingRightGroup.position.x = THREE.MathUtils.lerp(2.3, 2.8, t);
      wingRightGroup.position.y = THREE.MathUtils.lerp(1.3, 1.6, t);
      wingRightGroup.position.z = THREE.MathUtils.lerp(0.1, 0.6, t);
      wingRightGroup.rotation.y = THREE.MathUtils.lerp(0.4, 0.8, t);

      // Crimson core articulates into center stage!
      crimsonCoreGroup.position.x = THREE.MathUtils.lerp(1.6, 0.3, t);
      crimsonCoreGroup.position.y = THREE.MathUtils.lerp(-0.1, 0.1, t);
      crimsonCoreGroup.position.z = THREE.MathUtils.lerp(0.2, 0.9, t);
      crimsonCoreGroup.rotation.y = THREE.MathUtils.lerp(-0.3, 0.3, t);
      crimsonCoreGroup.scale.setScalar(THREE.MathUtils.lerp(1.0, 1.25, t));

      redPointLight.position.set(
        crimsonCoreGroup.position.x,
        crimsonCoreGroup.position.y + 0.1,
        crimsonCoreGroup.position.z + 0.2
      );
      redPointLight.intensity = THREE.MathUtils.lerp(2.8, 5.5, t);
      contactShadow.material.opacity = THREE.MathUtils.lerp(shadowBase * 1.05, shadowBase * 0.5, t);

      porcelainMat.opacity = 1.0;
      frostedGlassMat.opacity = 0.92;
      crimsonCoreMat.opacity = 1.0;
    }
    // Phase D: Crimson enters the white world (0.32 <= p < 0.40)
    // Red radiance floods the center, white background shifts to dark void
    else if (p >= 0.32 && p < 0.40) {
      const t = (p - 0.32) / 0.08; // 0 -> 1

      rootGroup.position.x = THREE.MathUtils.lerp(0.0, -0.05, t);
      rootGroup.position.y = THREE.MathUtils.lerp(-0.04, -0.08, t);
      rootGroup.position.z = THREE.MathUtils.lerp(0.55, 0.95, t);

      rootGroup.rotation.x = THREE.MathUtils.lerp(0.32, 0.42, t);
      rootGroup.rotation.y = THREE.MathUtils.lerp(0.65, 0.95, t);

      // Crimson core takes center stage with glowing ruby finish
      crimsonCoreGroup.position.x = THREE.MathUtils.lerp(0.3, 0.05, t);
      crimsonCoreGroup.position.z = THREE.MathUtils.lerp(0.9, 1.4, t);
      crimsonCoreGroup.scale.setScalar(THREE.MathUtils.lerp(1.25, 1.4, t));

      redPointLight.position.set(0.05, 0.0, 1.6);
      redPointLight.intensity = THREE.MathUtils.lerp(5.5, 8.0, t);
      crimsonCoreMat.emissiveIntensity = THREE.MathUtils.lerp(0.75, 1.5, t);

      studioKeyLight.intensity = THREE.MathUtils.lerp(keyBase * 1.15, 0.4, t);
      studioFillLight.intensity = THREE.MathUtils.lerp(fillBase * 1.1, 0.2, t);

      rootGroup.scale.setScalar(THREE.MathUtils.lerp(1.08, 1.18, t));
      contactShadow.material.opacity = THREE.MathUtils.lerp(shadowBase * 0.5, 0.0, t);

      porcelainMat.opacity = 1.0;
      frostedGlassMat.opacity = 0.92;
      crimsonCoreMat.opacity = 1.0;
    }
    // Phase E: Transition into dark void (0.40 <= p <= 0.48)
    // Camera glides through opening into depth; sculpture fades into void
    else if (p >= 0.40 && p <= 0.48) {
      const t = (p - 0.40) / 0.08; // 0 -> 1

      rootGroup.position.z = THREE.MathUtils.lerp(0.95, 2.2, t);
      rootGroup.scale.setScalar(THREE.MathUtils.lerp(1.18, 1.45, t));

      const alpha = Math.max(0, 1.0 - t);
      porcelainMat.opacity = alpha;
      frostedGlassMat.opacity = alpha * 0.92;
      crimsonCoreMat.opacity = alpha;
      porcelainMat.transparent = true;
      crimsonCoreMat.transparent = true;

      redPointLight.intensity = THREE.MathUtils.lerp(8.0, 0.0, t);
      studioKeyLight.intensity = 0;
      studioFillLight.intensity = 0;
      contactShadow.visible = false;
    }
  };

  const dispose = () => {
    scene.remove(rootGroup);
    scene.remove(studioKeyLight);
    scene.remove(studioFillLight);
    scene.remove(contactShadow);

    ribbonGeo.dispose();
    spineGeo.dispose();
    inlayGeo.dispose();
    glassBladeGeo.dispose();
    crimsonBladeGeo.dispose();
    wingLeftGeo.dispose();
    wingRightGeo.dispose();
    shadowGeo.dispose();
    contactShadowTexture.dispose();

    porcelainMat.dispose();
    titaniumMat.dispose();
    frostedGlassMat.dispose();
    graphiteMat.dispose();
    crimsonCoreMat.dispose();
    shadowMat.dispose();
  };

  return {
    group: rootGroup,
    update,
    dispose,
    redPointLight,
    studioKeyLight,
    studioFillLight,
    contactShadow,
  };
}

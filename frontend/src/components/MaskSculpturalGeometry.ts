import * as THREE from 'three';

/**
 * MaskSculpturalGeometry
 *
 * Replaces the generic wireframe node-web with a bespoke, art-directed
 * architectural 3D geometric framework emerging from the white mask.
 *
 * Features:
 * - Fine crimson contour curves tracing selected contours of the mask and extending into 3D space
 * - Spatial intersecting splines following deliberate architectural paths
 * - Angular dark graphite planes with restrained red specular reflections
 * - Translucent smoked crimson geometric facets creating depth and clean negative space
 * - Choreographed expansion driven smoothly by scroll progress
 */

export interface MaskSculptureController {
  group: THREE.Group;
  update: (progress: number, elapsedTime: number, mouseX: number, mouseY: number) => void;
  dispose: () => void;
}

export function createMaskSculpturalGeometry(): MaskSculptureController {
  const group = new THREE.Group();
  group.name = 'MaskSculpturalGeometry';

  const disposables: (THREE.BufferGeometry | THREE.Material)[] = [];

  // =========================================================================
  // 1. MATERIALS: Restrained Crimson Lacquer, Dark Graphite & Smoked Glass
  // =========================================================================

  // Crimson Contour Ribbon Material
  const crimsonRibbonMaterial = new THREE.MeshStandardMaterial({
    color: 0xf43f5e,
    emissive: 0x9f1239,
    emissiveIntensity: 0.9,
    roughness: 0.18,
    metalness: 0.85,
  });
  disposables.push(crimsonRibbonMaterial);

  // Secondary Fine Spatial Line Material
  const spatialSplineMaterial = new THREE.MeshStandardMaterial({
    color: 0xeb173e,
    emissive: 0x6e0819,
    emissiveIntensity: 0.6,
    roughness: 0.25,
    metalness: 0.75,
  });
  disposables.push(spatialSplineMaterial);

  // Dark Graphite Architectural Plane Material
  const darkGraphiteMaterial = new THREE.MeshStandardMaterial({
    color: 0x121318,
    roughness: 0.22,
    metalness: 0.92,
  });
  disposables.push(darkGraphiteMaterial);

  // Translucent Smoked Crimson Glass Facet Material
  const smokedCrimsonGlass = new THREE.MeshPhysicalMaterial({
    color: 0x220509,
    roughness: 0.16,
    transmission: 0.82,
    thickness: 0.08,
    ior: 1.52,
    transparent: true,
    opacity: 0.88,
    attenuationColor: new THREE.Color(0xf43f5e),
    attenuationDistance: 0.6,
  });
  disposables.push(smokedCrimsonGlass);

  // Titanium Bevel Edge Line Material
  const edgeLineMaterial = new THREE.LineBasicMaterial({
    color: 0xff3352,
    transparent: true,
    opacity: 0.75,
  });
  disposables.push(edgeLineMaterial);

  // =========================================================================
  // 2. CONTOUR CURVES TRACING MASK & SWOOPING INTO 3D SPACE
  // =========================================================================

  const curvesGroup = new THREE.Group();
  group.add(curvesGroup);

  // Curve 1: Right Cheekbone & Jaw Contour Arc -> Swoops into space
  const spline1Points = [
    new THREE.Vector3(0.35, 0.45, 0.42),
    new THREE.Vector3(0.72, 0.15, 0.48),
    new THREE.Vector3(0.88, -0.28, 0.35),
    new THREE.Vector3(1.35, -0.65, 0.12),
    new THREE.Vector3(1.95, -0.92, -0.25),
  ];
  const curve1 = new THREE.CatmullRomCurve3(spline1Points);
  const geo1 = new THREE.TubeGeometry(curve1, 80, 0.013, 8, false);
  const mesh1 = new THREE.Mesh(geo1, crimsonRibbonMaterial);
  curvesGroup.add(mesh1);
  disposables.push(geo1);

  // Curve 2: Left Forehead Brow Arc -> Bridges toward center-left
  const spline2Points = [
    new THREE.Vector3(-0.15, 0.72, 0.46),
    new THREE.Vector3(-0.58, 0.58, 0.38),
    new THREE.Vector3(-0.95, 0.85, 0.18),
    new THREE.Vector3(-1.45, 1.25, -0.15),
    new THREE.Vector3(-1.85, 1.45, -0.45),
  ];
  const curve2 = new THREE.CatmullRomCurve3(spline2Points);
  const geo2 = new THREE.TubeGeometry(curve2, 80, 0.012, 8, false);
  const mesh2 = new THREE.Mesh(geo2, crimsonRibbonMaterial);
  curvesGroup.add(mesh2);
  disposables.push(geo2);

  // Curve 3: Chin / Jaw Under-Sweep -> Architectural ground curve
  const spline3Points = [
    new THREE.Vector3(-0.25, -0.75, 0.35),
    new THREE.Vector3(0.05, -0.85, 0.45),
    new THREE.Vector3(0.55, -0.78, 0.32),
    new THREE.Vector3(1.15, -0.55, 0.05),
    new THREE.Vector3(1.75, -0.25, -0.35),
  ];
  const curve3 = new THREE.CatmullRomCurve3(spline3Points);
  const geo3 = new THREE.TubeGeometry(curve3, 80, 0.011, 8, false);
  const mesh3 = new THREE.Mesh(geo3, spatialSplineMaterial);
  curvesGroup.add(mesh3);
  disposables.push(geo3);

  // Curve 4: High Crown Halo Arc (intersects mask top contour)
  const spline4Points = [
    new THREE.Vector3(-0.85, 0.35, -0.1),
    new THREE.Vector3(-0.45, 0.95, 0.28),
    new THREE.Vector3(0.25, 1.15, 0.32),
    new THREE.Vector3(0.85, 0.85, 0.15),
    new THREE.Vector3(1.45, 0.35, -0.15),
  ];
  const curve4 = new THREE.CatmullRomCurve3(spline4Points);
  const geo4 = new THREE.TubeGeometry(curve4, 80, 0.012, 8, false);
  const mesh4 = new THREE.Mesh(geo4, spatialSplineMaterial);
  curvesGroup.add(mesh4);
  disposables.push(geo4);

  // Curve 5: Orbital Brow & Temple Ridge Sweep (traces outer cranial contour)
  const spline5Points = [
    new THREE.Vector3(-0.75, 0.45, 0.15),
    new THREE.Vector3(-0.35, 0.82, 0.38),
    new THREE.Vector3(0.35, 0.85, 0.36),
    new THREE.Vector3(0.85, 0.52, 0.18),
    new THREE.Vector3(1.45, 0.22, -0.2),
  ];
  const curve5 = new THREE.CatmullRomCurve3(spline5Points);
  const geo5 = new THREE.TubeGeometry(curve5, 70, 0.010, 8, false);
  const mesh5 = new THREE.Mesh(geo5, crimsonRibbonMaterial);
  curvesGroup.add(mesh5);
  disposables.push(geo5);

  // =========================================================================
  // 3. ANGULAR PLANES & TRANSLUCENT GEOMETRIC FACETS (ARCHITECTURAL SCULPTURE)
  // =========================================================================

  const planesGroup = new THREE.Group();
  group.add(planesGroup);

  // Facet 1: Dark Graphite Triangular Fin (Right rear framing)
  const shape1 = new THREE.Shape();
  shape1.moveTo(0, 0);
  shape1.lineTo(1.1, -0.4);
  shape1.lineTo(0.7, 0.85);
  shape1.closePath();

  const geomFacet1 = new THREE.ExtrudeGeometry(shape1, {
    depth: 0.025,
    bevelEnabled: true,
    bevelSegments: 2,
    steps: 1,
    bevelSize: 0.012,
    bevelThickness: 0.012,
  });
  const meshFacet1 = new THREE.Mesh(geomFacet1, darkGraphiteMaterial);
  meshFacet1.position.set(0.65, -0.25, -0.25);
  meshFacet1.rotation.set(0.15, -0.35, 0.1);
  planesGroup.add(meshFacet1);
  disposables.push(geomFacet1);

  // Facet 2: Translucent Smoked Crimson Glass Shard (Angled blade)
  const shape2 = new THREE.Shape();
  shape2.moveTo(0, 0);
  shape2.lineTo(0.9, 0.65);
  shape2.lineTo(0.4, 1.25);
  shape2.lineTo(-0.25, 0.85);
  shape2.closePath();

  const geomFacet2 = new THREE.ExtrudeGeometry(shape2, {
    depth: 0.015,
    bevelEnabled: true,
    bevelSegments: 2,
    steps: 1,
    bevelSize: 0.008,
    bevelThickness: 0.008,
  });
  const meshFacet2 = new THREE.Mesh(geomFacet2, smokedCrimsonGlass);
  meshFacet2.position.set(-0.95, -0.15, -0.18);
  meshFacet2.rotation.set(-0.25, 0.45, -0.15);
  planesGroup.add(meshFacet2);
  disposables.push(geomFacet2);

  // Fine crimson wire outline on the glass shard
  const edges2 = new THREE.EdgesGeometry(geomFacet2);
  const line2 = new THREE.LineSegments(edges2, edgeLineMaterial);
  meshFacet2.add(line2);
  disposables.push(edges2);

  // Facet 3: Lower Anchor Graphite Horizon Wedge
  const shape3 = new THREE.Shape();
  shape3.moveTo(-0.6, -0.1);
  shape3.lineTo(1.2, -0.18);
  shape3.lineTo(0.9, -0.45);
  shape3.lineTo(-0.4, -0.42);
  shape3.closePath();

  const geomFacet3 = new THREE.ExtrudeGeometry(shape3, {
    depth: 0.02,
    bevelEnabled: true,
    bevelSegments: 2,
    steps: 1,
    bevelSize: 0.01,
    bevelThickness: 0.01,
  });
  const meshFacet3 = new THREE.Mesh(geomFacet3, darkGraphiteMaterial);
  meshFacet3.position.set(0.15, -0.85, 0.05);
  meshFacet3.rotation.set(0.4, -0.1, 0.05);
  planesGroup.add(meshFacet3);
  disposables.push(geomFacet3);

  // Facet 4: Slender Upper Titanium Accent Blade
  const shape4 = new THREE.Shape();
  shape4.moveTo(0, 0);
  shape4.lineTo(0.2, 0.95);
  shape4.lineTo(0.08, 1.15);
  shape4.lineTo(-0.1, 0.45);
  shape4.closePath();

  const geomFacet4 = new THREE.ExtrudeGeometry(shape4, {
    depth: 0.015,
    bevelEnabled: true,
    bevelSegments: 2,
    steps: 1,
    bevelSize: 0.008,
    bevelThickness: 0.008,
  });
  const meshFacet4 = new THREE.Mesh(geomFacet4, darkGraphiteMaterial);
  meshFacet4.position.set(0.85, 0.35, -0.15);
  meshFacet4.rotation.set(-0.1, 0.25, -0.2);
  planesGroup.add(meshFacet4);
  disposables.push(geomFacet4);

  // =========================================================================
  // 4. RESTRICTED LOCAL LIGHTING FOR SPECULAR GLINTS & CONTOUR HIGHLIGHTS
  // =========================================================================

  const crimsonHighlightLight = new THREE.PointLight(0xf43f5e, 2.5, 4.5);
  crimsonHighlightLight.position.set(1.2, 0.3, 1.2);
  group.add(crimsonHighlightLight);

  const whiteRimGlint = new THREE.PointLight(0xffffff, 1.4, 3.5);
  whiteRimGlint.position.set(-0.8, 0.9, 1.0);
  group.add(whiteRimGlint);

  // =========================================================================
  // 5. UPDATE CONTROLLER
  // =========================================================================

  const update = (scrollProgress: number, elapsedTime: number, mouseX: number, mouseY: number) => {
    // Active range for the mask sequence: 0.76 <= p < 0.92
    if (scrollProgress < 0.76 || scrollProgress >= 0.92) {
      group.visible = false;
      return;
    }

    group.visible = true;

    // Emergence progress factor: 0.77 -> 0.88
    const tEmergence = Math.max(0, Math.min(1, (scrollProgress - 0.77) / 0.11));

    // Group follows mask position and slight mouse parallax
    // At t=0: tightly centered near mask
    // As t expands: curves and facets unfurl into an art-directed asymmetric framework
    const expandScale = THREE.MathUtils.lerp(0.35, 1.0, tEmergence);
    curvesGroup.scale.set(expandScale, expandScale, expandScale);
    planesGroup.scale.set(expandScale, expandScale, expandScale);

    // Subtle breathing rotation & gentle parallax
    curvesGroup.rotation.y = mouseX * 0.2 + Math.sin(elapsedTime * 0.8) * 0.03;
    curvesGroup.rotation.x = mouseY * 0.15 + Math.cos(elapsedTime * 0.7) * 0.02;

    planesGroup.rotation.y = mouseX * 0.15 + Math.sin(elapsedTime * 0.6) * 0.02;
    planesGroup.rotation.x = mouseY * 0.1;

    // Facet micro-articulations
    meshFacet1.rotation.y = -0.35 + Math.sin(elapsedTime * 1.1) * 0.04;
    meshFacet2.rotation.z = -0.15 + Math.cos(elapsedTime * 0.9) * 0.03;

    // Dynamic light pulsing for contour glints
    crimsonHighlightLight.intensity = (2.2 + Math.sin(elapsedTime * 2.2) * 0.8) * tEmergence;
    whiteRimGlint.intensity = (1.2 + Math.cos(elapsedTime * 1.8) * 0.4) * tEmergence;

    // Opacity & emissive strength scaling
    crimsonRibbonMaterial.emissiveIntensity = 0.5 + tEmergence * 0.6;
    spatialSplineMaterial.emissiveIntensity = 0.3 + tEmergence * 0.5;
  };

  const dispose = () => {
    disposables.forEach((item) => {
      item.dispose();
    });
  };

  return {
    group,
    update,
    dispose,
  };
}
